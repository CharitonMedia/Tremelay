package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCheckpointFormat(t *testing.T) {
	cp := Checkpoint{
		VaultID:  strings.Repeat("ab", 16),
		AuditSeq: 12,
		AuditTip: strings.Repeat("ef", 32),
		Digest:   strings.Repeat("ab", 32),
	}
	encoded, err := cp.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var got Checkpoint
	if err := got.UnmarshalText(encoded); err != nil {
		t.Fatal(err)
	}
	if got != cp {
		t.Fatalf("%+v", got)
	}
	if err := got.UnmarshalText(append(append([]byte{}, encoded...), '\n')); err != nil || got != cp {
		t.Fatalf("%v %+v", err, got)
	}
	body := string(encoded)
	bad := []string{
		"",
		"tremelay-checkpoint-v1\n",
		body + "\nextra x",
		strings.Replace(body, "vault ", "id ", 1),
		strings.Replace(body, "sha256 "+cp.Digest, "sha256 "+strings.ToUpper(cp.Digest), 1),
		strings.Replace(body, "\nseq 12\n", "\nseq 01\n", 1),
		strings.Replace(body, "\nseq 12\n", "\nseq 0\n", 1),
		// The retired M9a organization line is not accepted back.
		strings.Replace(body, "\nseq 12\n", "\norg -\nseq 12\n", 1),
		strings.ReplaceAll(body, "\n", "\r\n"),
		body + "\n\n",
	}
	for _, item := range bad {
		var out Checkpoint
		if err := out.UnmarshalText([]byte(item)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted %q %v", item, err)
		}
	}
	upper := cp
	upper.Digest = strings.ToUpper(cp.Digest)
	if err := upper.canonical(); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestBackupRestoreSyntheticDemo(t *testing.T) {
	var logBuf bytes.Buffer
	logger := log.New(&logBuf, "", 0)
	env := newAttestEnvLog(t, &logBuf)
	env.path = canonicalExisting(t, env.path)
	grant := env.grant(t, time.Hour)
	payload := []byte("m9b-demo-artifact")
	if !verifyAttest(t, env, payload) {
		t.Fatal("source attestation")
	}
	srcHash := readAll(t, env.path)
	dir := canonicalTemp(t)
	art, cp := mustBackup(t, env.path, dir, env.pass, logger)
	if cp.VaultID != env.s.id || cp.AuditSeq == 0 {
		t.Fatalf("%+v", cp)
	}
	text, err := cp.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, text, env.pass, env.der)
	assertNoSecret(t, logBuf.Bytes(), env.pass, env.der)
	if !bytes.Equal(readAll(t, env.path), srcHash) {
		t.Fatal("backup changed the source")
	}
	assertMode(t, art)
	sum, err := fileSHA256(art)
	if err != nil || sum != cp.Digest {
		t.Fatal("digest")
	}
	// A manifest beside the artifact is not the checkpoint Restore uses.
	if err := os.WriteFile(art+".manifest", []byte("vault stolen\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "restored.db")
	if err := Restore(art, dest, env.pass, cp, logger); err != nil {
		t.Fatal(err)
	}
	assertMode(t, dest)
	if !bytes.Equal(readAll(t, env.path), srcHash) || !bytes.Equal(readAll(t, art), readAll(t, dest)) {
		t.Fatal("restore changed the source or the published bytes")
	}
	assertNoSecret(t, logBuf.Bytes(), env.pass, env.der)
	opened := mustUnlock(t, dest, env.pass)
	if opened.id != env.s.id {
		t.Fatal("restored identity")
	}
	if !grantKept(opened, grant.ID) {
		t.Fatal("restored grant")
	}
	opened.Lock()
	opened = mustUnlock(t, dest, env.pass)
	envRestored := *env
	envRestored.s = opened
	envRestored.path = dest
	if !verifyAttest(t, &envRestored, payload) {
		t.Fatal("restored attestation")
	}
	opened.clock = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := attestErr(t, &envRestored, payload); !errors.Is(err, ErrDeniedExpired) {
		t.Fatalf("expiry %v", err)
	}
	opened.clock = nil
	if !verifyAttest(t, &envRestored, payload) {
		t.Fatal("expiry did not stay on the clock")
	}
	if err := opened.RevokeGrant(grant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := attestErr(t, &envRestored, payload); !errors.Is(err, ErrDeniedRevoked) {
		t.Fatalf("revoked %v", err)
	}
	if bytes.Contains(logBuf.Bytes(), payload) {
		t.Fatal("log leaked the payload")
	}
}

func TestBackupRestoreNegative(t *testing.T) {
	env := newAttestEnv(t)
	env.path = canonicalExisting(t, env.path)
	dir := canonicalTemp(t)
	artUngranted, cpUngranted := mustBackup(t, env.path, dir, env.pass, nil)
	env.grant(t, time.Hour)
	artGranted, cpGranted := mustBackup(t, env.path, dir, env.pass, nil)
	mustReject(t, artUngranted, env.pass, cpGranted, ErrCheckpoint)
	t.Run("staging overwritten before publish", func(t *testing.T) {
		restorePublishFault = func() error {
			names := incompleteNames(t, dir)
			if len(names) != 1 {
				return errors.New("staging-count-sentinel")
			}
			return os.WriteFile(filepath.Join(dir, names[0]), readAll(t, artUngranted), 0o600)
		}
		t.Cleanup(func() { restorePublishFault = nil })
		dest := filepath.Join(dir, "stale-race.db")
		if err := Restore(artGranted, dest, env.pass, cpGranted, nil); !errors.Is(err, ErrCheckpoint) {
			t.Fatalf("stale staging publication: %v", err)
		}
		if _, err := os.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("stale staging publication left a destination")
		}
		assertNoIncomplete(t, dir)
	})
	// The pre-grant artifact still matches the checkpoint issued for it.
	// That pair is stale against the granted source, and this reference cannot tell.
	ungrantedDest := filepath.Join(canonicalTemp(t), "ungranted.db")
	if err := Restore(artUngranted, ungrantedDest, env.pass, cpUngranted, nil); err != nil {
		t.Fatal(err)
	}
	ungranted := mustUnlock(t, ungrantedDest, env.pass)
	if len(ungranted.grants) != 0 {
		t.Fatal("old checkpoint revived an issued grant")
	}
	ungranted.Lock()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.Replace(env.cred.ID, der, LifecycleOptions{}); err != nil {
		t.Fatal(err)
	}
	artKey, cpKey := mustBackup(t, env.path, dir, env.pass, nil)
	mustReject(t, artGranted, env.pass, cpKey, ErrCheckpoint)
	keyDest := filepath.Join(canonicalTemp(t), "replaced.db")
	if err := Restore(artKey, keyDest, env.pass, cpKey, nil); err != nil {
		t.Fatal(err)
	}
	keySession := mustUnlock(t, keyDest, env.pass)
	keyEnv := *env
	keyEnv.s = keySession
	keyEnv.path = keyDest
	if _, err := attestErr(t, &keyEnv, []byte("m9b-replaced")); !errors.Is(err, ErrDeniedKey) {
		t.Fatalf("replaced key %v", err)
	}
	keySession.Lock()

	if err := env.s.RevokeGrant(env.s.grants[0].ID); err != nil {
		t.Fatal(err)
	}
	artRevoked, cpRevoked := mustBackup(t, env.path, dir, env.pass, nil)
	mustReject(t, artKey, env.pass, cpRevoked, ErrCheckpoint)
	revokedDest := filepath.Join(canonicalTemp(t), "revoked.db")
	if err := Restore(artRevoked, revokedDest, env.pass, cpRevoked, nil); err != nil {
		t.Fatal(err)
	}
	revoked := mustUnlock(t, revokedDest, env.pass)
	revokedEnv := *env
	revokedEnv.s = revoked
	revokedEnv.path = revokedDest
	if _, err := attestErr(t, &revokedEnv, []byte("m9b-revoked")); !errors.Is(err, ErrDeniedRevoked) {
		t.Fatalf("revoked restore %v", err)
	}
	revoked.Lock()

	if _, err := env.s.CreateAgent("worker-2"); err != nil {
		t.Fatal(err)
	}
	_, cpAgent := mustBackup(t, env.path, dir, env.pass, nil)
	mustReject(t, artRevoked, env.pass, cpAgent, ErrCheckpoint)

	if err := env.s.SetNotifier(&MemoryNotifier{}); err != nil {
		t.Fatal(err)
	}
	if err := env.s.SetResponsePolicy(ResponsePolicy{High: ContainSuspendAgent}); err != nil {
		t.Fatal(err)
	}
	if _, err := attestErr(t, env, []byte("m9b-contain")); !errors.Is(err, ErrDeniedRevoked) {
		t.Fatalf("contain attempt %v", err)
	}
	suspended := false
	contained := false
	for _, agent := range env.s.agents {
		if agent.ID == env.agent.ID && agent.State == agentStateSuspended {
			suspended = true
		}
	}
	for _, ev := range env.s.audit {
		if ev.Action == actionContain {
			contained = true
		}
	}
	if !suspended || !contained {
		t.Fatal("containment did not stick")
	}
	artContain, cpContain := mustBackup(t, env.path, dir, env.pass, nil)
	mustReject(t, artKey, env.pass, cpContain, ErrCheckpoint)
	containDest := filepath.Join(canonicalTemp(t), "contained.db")
	if err := Restore(artContain, containDest, env.pass, cpContain, nil); err != nil {
		t.Fatal(err)
	}
	containedSession := mustUnlock(t, containDest, env.pass)
	still := false
	for _, agent := range containedSession.agents {
		if agent.ID == env.agent.ID && agent.State == agentStateSuspended {
			still = true
		}
	}
	if !still {
		t.Fatal("containment dropped on restore")
	}
	containEnv := *env
	containEnv.s = containedSession
	containEnv.path = containDest
	if _, err := attestErr(t, &containEnv, []byte("m9b-contain-again")); !errors.Is(err, ErrDeniedAgent) {
		t.Fatalf("contained restore %v", err)
	}
	containedSession.Lock()

	sameDigest := cpGranted
	sameDigest.AuditSeq++
	mustReject(t, artGranted, env.pass, sameDigest, ErrCheckpoint)
	sameDigest = cpGranted
	sameDigest.AuditTip = strings.Repeat("ab", 32)
	mustReject(t, artGranted, env.pass, sameDigest, ErrCheckpoint)
	sameDigest = cpGranted
	sameDigest.VaultID = strings.Repeat("cd", 16)
	mustReject(t, artGranted, env.pass, sameDigest, ErrCheckpoint)
	missing := cpGranted
	missing.Digest = ""
	mustReject(t, artGranted, env.pass, missing, ErrInvalid)

	wrong := []byte("wrong-passphrase-value")
	artHash := readAll(t, artGranted)
	if err := Restore(artGranted, filepath.Join(canonicalTemp(t), "nope.db"), wrong, cpGranted, nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
	if !bytes.Equal(readAll(t, artGranted), artHash) {
		t.Fatal("failed restore changed the artifact")
	}
	leftover := filepath.Join(dir, "leftover.db")
	if _, err := Backup(env.path, leftover, wrong, nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(leftover); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed backup left an artifact")
	}

	corrupt := append([]byte{}, artHash...)
	corrupt[len(corrupt)/2] ^= 0xff
	bad := filepath.Join(dir, "corrupt.db")
	if err := os.WriteFile(bad, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	mustReject(t, bad, env.pass, cpGranted, ErrCheckpoint)
	badSum, err := fileSHA256(bad)
	if err != nil {
		t.Fatal(err)
	}
	badCP := cpGranted
	badCP.Digest = badSum
	dest := filepath.Join(canonicalTemp(t), "bad-dest.db")
	err = Restore(bad, dest, env.pass, badCP, nil)
	if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrAudit) && !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("corrupt %v", err)
	}
	if _, statErr := os.Lstat(dest); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("corrupt restore published")
	}
	if !bytes.Equal(readAll(t, artGranted), artHash) {
		t.Fatal("corrupt test changed the original artifact")
	}

	occupied := filepath.Join(dir, "occupied.db")
	if err := os.WriteFile(occupied, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Restore(artGranted, occupied, env.pass, cpGranted, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if string(readAll(t, occupied)) != "keep" {
		t.Fatal("destination overwritten")
	}
	if err := Restore(artGranted, env.path, env.pass, cpGranted, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	linkDest := filepath.Join(dir, "alias.db")
	if err := os.Symlink(artGranted, linkDest); err != nil {
		if runtime.GOOS == "windows" {
			t.Log("symlink skipped")
		} else {
			t.Fatal(err)
		}
	} else if err := Restore(artGranted, linkDest, env.pass, cpGranted, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	real := canonicalTemp(t)
	parentLink := filepath.Join(dir, "parent-link")
	if err := os.Symlink(real, parentLink); err == nil {
		if err := Restore(artGranted, filepath.Join(parentLink, "vault.db"), env.pass, cpGranted, nil); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(real)
		if err != nil || len(entries) != 0 {
			t.Fatal("followed a parent alias")
		}
	}

	var logged bytes.Buffer
	faultLogger := log.New(&logged, "", 0)
	restorePublishFault = func() error { return errors.New("caller-body-sentinel") }
	defer func() { restorePublishFault = nil }()
	faultDest := filepath.Join(dir, "fault.db")
	err = Restore(artGranted, faultDest, env.pass, cpGranted, faultLogger)
	if !errors.Is(err, ErrIO) || strings.Contains(err.Error(), "caller-body-sentinel") || strings.Contains(logged.String(), "caller-body-sentinel") {
		t.Fatalf("%v %s", err, logged.String())
	}
	if _, statErr := os.Lstat(faultDest); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("failed publication left a destination")
	}
	assertNoIncomplete(t, dir)
	if !bytes.Equal(readAll(t, artGranted), artHash) {
		t.Fatal("failed publication changed the artifact")
	}
	restorePublishFault = nil
	if err := Restore(artGranted, faultDest, env.pass, cpGranted, nil); err != nil {
		t.Fatal(err)
	}

	t.Run("single-user suffix", func(t *testing.T) {
		path, pass, session := mustCreate(t, nil)
		secret := randBytesT(t, 24)
		cred, err := session.Put("solo", "generic", secret, PutOptions{})
		if err != nil {
			t.Fatal(err)
		}
		session.Lock()
		if _, err := Unlock(path, []byte("wrong-passphrase-value"), nil); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal(err)
		}
		art, cp := mustBackup(t, path, canonicalTemp(t), pass, nil)
		events := mustAudit(t, path)
		tip := events[len(events)-1]
		head := events[len(events)-2]
		if tip.Action != actionUnlock || tip.Result != resultDenied || cp.AuditTip != tip.Hash || cp.AuditSeq != tip.Seq {
			t.Fatalf("tip %+v cp %+v", tip, cp)
		}
		if cp.AuditTip == head.Hash {
			t.Fatal("checkpoint ignored the denial suffix")
		}
		forged := cp
		forged.AuditSeq = head.Seq
		forged.AuditTip = head.Hash
		mustReject(t, art, pass, forged, ErrCheckpoint)
		dest := filepath.Join(canonicalTemp(t), "solo.db")
		var buf bytes.Buffer
		if err := Restore(art, dest, pass, cp, log.New(&buf, "", 0)); err != nil {
			t.Fatal(err)
		}
		assertNoSecret(t, buf.Bytes(), pass, secret)
		text, err := cp.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		assertNoSecret(t, text, pass, secret)
		mustReject(t, art, pass, cpGranted, ErrCheckpoint)
		opened := mustUnlock(t, dest, pass)
		again := opened.audit
		if again[len(again)-1].Action != actionUnlock || again[len(again)-1].Result != resultAllowed || again[len(again)-2].Result != resultDenied {
			t.Fatal("unlock did not keep the denial suffix")
		}
		got, err := opened.Get(cred.ID)
		if err != nil || !bytes.Equal(got.Secret, secret) {
			t.Fatal("restored secret")
		}
		opened.Lock()
	})
}

func TestBackupMigratesLegacyAuditSchema(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	id := session.id
	session.Lock()
	path = canonicalExisting(t, path)
	// Same M1 fixture Unlock already accepts: base audit columns only.
	// A current health row cannot be stripped this way; its hash still
	// covers reasons and cred_gen.
	rewriteAudit(t, path, false)
	before := readAll(t, path)
	if auditReady(t, path) {
		t.Fatal("fixture still has the current audit schema")
	}
	sourceHash := auditSeqHash(t, path)
	dir := canonicalTemp(t)
	art, cp := mustBackup(t, path, dir, pass, nil)
	if !bytes.Equal(readAll(t, path), before) || auditReady(t, path) {
		t.Fatal("backup migrated the source")
	}
	if !auditReady(t, art) || auditSeqHash(t, art) != sourceHash {
		t.Fatal("artifact schema or audit hash")
	}
	sum, err := fileSHA256(art)
	if err != nil || sum != cp.Digest {
		t.Fatal("digest")
	}
	assertMode(t, art)
	dest := filepath.Join(dir, "restored.db")
	if err := Restore(art, dest, pass, cp, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAudit(dest, pass); err != nil {
		t.Fatal(err)
	}
	opened := mustUnlock(t, dest, pass)
	if opened.id != id {
		t.Fatal("restored identity")
	}
	opened.Lock()
	leftover := filepath.Join(dir, "leftover.db")
	if _, err := Backup(path, leftover, []byte("wrong-passphrase-value"), nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
	if _, statErr := os.Lstat(leftover); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("failed backup left an artifact")
	}
	if !bytes.Equal(readAll(t, path), before) {
		t.Fatal("failed backup changed the source")
	}
}

func TestBackupPathRequiresCanonicalAncestor(t *testing.T) {
	base := canonicalTemp(t)
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "alias")
	if err := os.Symlink(real, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Log("symlink skipped")
			return
		}
		t.Fatal(err)
	}
	if _, err := cleanPath(filepath.Join(link, "vault.db"), true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("alias ancestor %v", err)
	}
	if got, err := cleanPath(filepath.Join(real, "vault.db"), true); err != nil || got != filepath.Join(real, "vault.db") {
		t.Fatalf("%s %v", got, err)
	}
}

func TestBackupRestorePublication(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	id := session.id
	session.Lock()
	path = canonicalExisting(t, path)
	source := readAll(t, path)
	dir := canonicalTemp(t)
	artPath := filepath.Join(dir, "art.db")
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		side := artPath + suffix
		payload := []byte("keep" + suffix)
		if err := os.WriteFile(side, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Backup(path, artPath, pass, nil); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s %v", suffix, err)
		}
		if _, statErr := os.Lstat(artPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("%s backup created an artifact", suffix)
		}
		if !bytes.Equal(readAll(t, side), payload) || !bytes.Equal(readAll(t, path), source) {
			t.Fatalf("%s backup changed an unowned file", suffix)
		}
		if err := os.Remove(side); err != nil {
			t.Fatal(err)
		}
	}

	art, cp := mustBackup(t, path, dir, pass, nil)
	artBytes := readAll(t, art)
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		dest := filepath.Join(dir, "sidecollide.db")
		side := dest + suffix
		payload := []byte("keep" + suffix)
		if err := os.WriteFile(side, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := Restore(art, dest, pass, cp, nil); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s %v", suffix, err)
		}
		if _, statErr := os.Lstat(dest); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("%s restore published beside a sidecar", suffix)
		}
		if !bytes.Equal(readAll(t, side), payload) || !bytes.Equal(readAll(t, art), artBytes) {
			t.Fatalf("%s restore changed an unowned file", suffix)
		}
		assertNoIncomplete(t, dir)
		if err := os.Remove(side); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("backup sync", func(t *testing.T) {
		ioFault = func(step string) error {
			if step == "backup-sync-dir" {
				return errors.New("backup-sync-sentinel")
			}
			return nil
		}
		t.Cleanup(func() { ioFault = nil })
		var logged bytes.Buffer
		dst := filepath.Join(canonicalTemp(t), "unsynced.db")
		_, err := Backup(path, dst, pass, log.New(&logged, "", 0))
		if !errors.Is(err, ErrIO) || strings.Contains(err.Error(), "sentinel") || strings.Contains(logged.String(), "sentinel") {
			t.Fatalf("%v %s", err, logged.String())
		}
		if _, statErr := os.Lstat(dst); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("unsynced backup left an artifact")
		}
		for _, suffix := range []string{"-journal", "-wal", "-shm"} {
			if _, statErr := os.Lstat(dst + suffix); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("unsynced backup left %s", suffix)
			}
		}
	})

	restoreFault := func(t *testing.T, steps ...string) {
		t.Helper()
		ioFault = func(step string) error {
			for _, want := range steps {
				if step == want {
					return errors.New(want + "-sentinel")
				}
			}
			return nil
		}
		t.Cleanup(func() { ioFault = nil })
	}
	publishDir := func(t *testing.T) string {
		t.Helper()
		return canonicalTemp(t)
	}

	t.Run("chmod", func(t *testing.T) {
		restoreFault(t, "chmod")
		var logged bytes.Buffer
		destDir := publishDir(t)
		dest := filepath.Join(destDir, "vault.db")
		err := Restore(art, dest, pass, cp, log.New(&logged, "", 0))
		if !errors.Is(err, ErrIO) || errors.Is(err, ErrPublished) || strings.Contains(logged.String(), "sentinel") {
			t.Fatalf("%v %s", err, logged.String())
		}
		if _, statErr := os.Lstat(dest); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("chmod fault published a destination")
		}
		assertNoIncomplete(t, destDir)
	})

	t.Run("sync rollback", func(t *testing.T) {
		restoreFault(t, "sync")
		var logged bytes.Buffer
		destDir := publishDir(t)
		dest := filepath.Join(destDir, "vault.db")
		err := Restore(art, dest, pass, cp, log.New(&logged, "", 0))
		wantErr := ErrIO
		wantLog := "vault_restore result=failed"
		if runtime.GOOS == "windows" {
			// The read-only directory handle cannot confirm FlushFileBuffers.
			// A removed name must not be called a durably completed rollback.
			wantErr = ErrPublicationUncertain
			wantLog = "vault_restore result=publication_uncertain"
		}
		if !errors.Is(err, wantErr) || errors.Is(err, ErrPublished) || strings.Contains(logged.String(), "sentinel") ||
			!strings.Contains(logged.String(), wantLog) {
			t.Fatalf("%v %s", err, logged.String())
		}
		if _, statErr := os.Lstat(dest); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("rolled-back sync left a destination")
		}
		assertNoIncomplete(t, destDir)
	})

	t.Run("sync remains", func(t *testing.T) {
		restoreFault(t, "sync", "rollback")
		var logged bytes.Buffer
		destDir := publishDir(t)
		dest := filepath.Join(destDir, "vault.db")
		err := Restore(art, dest, pass, cp, log.New(&logged, "", 0))
		if !errors.Is(err, ErrPublished) || errors.Is(err, ErrIO) || strings.Contains(logged.String(), "sentinel") {
			t.Fatalf("%v %s", err, logged.String())
		}
		if !strings.Contains(logged.String(), "vault_restore result=published") {
			t.Fatalf("publication outcome missing: %s", logged.String())
		}
		if !bytes.Equal(readAll(t, dest), artBytes) {
			t.Fatal("remaining destination bytes")
		}
		opened := mustUnlock(t, dest, pass)
		if opened.id != id {
			t.Fatal("remaining destination identity")
		}
		assertNoIncomplete(t, destDir)
	})

	t.Run("rollback durability uncertain", func(t *testing.T) {
		restoreFault(t, "sync", "rollback-sync")
		var logged bytes.Buffer
		destDir := publishDir(t)
		dest := filepath.Join(destDir, "vault.db")
		err := Restore(art, dest, pass, cp, log.New(&logged, "", 0))
		if !errors.Is(err, ErrPublicationUncertain) || errors.Is(err, ErrPublished) || errors.Is(err, ErrIO) {
			t.Fatalf("rollback outcome %v", err)
		}
		if strings.Contains(err.Error(), "sentinel") || strings.Contains(logged.String(), "sentinel") ||
			!strings.Contains(logged.String(), "vault_restore result=publication_uncertain") {
			t.Fatalf("%v %s", err, logged.String())
		}
		if _, statErr := os.Lstat(dest); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("rollback did not remove the destination at return")
		}
		assertNoIncomplete(t, destDir)
	})

	t.Run("unlink remains", func(t *testing.T) {
		restoreFault(t, "unlink")
		var logged bytes.Buffer
		destDir := publishDir(t)
		dest := filepath.Join(destDir, "vault.db")
		err := Restore(art, dest, pass, cp, log.New(&logged, "", 0))
		if !errors.Is(err, ErrPublished) || errors.Is(err, ErrIO) || strings.Contains(logged.String(), "sentinel") {
			t.Fatalf("%v %s", err, logged.String())
		}
		if !strings.Contains(logged.String(), "vault_restore result=published") {
			t.Fatalf("publication outcome missing: %s", logged.String())
		}
		if !bytes.Equal(readAll(t, dest), artBytes) {
			t.Fatal("remaining destination bytes")
		}
		names := incompleteNames(t, destDir)
		if len(names) != 1 || !bytes.Equal(readAll(t, filepath.Join(destDir, names[0])), artBytes) {
			t.Fatalf("staging name %v", names)
		}
		opened := mustUnlock(t, dest, pass)
		if opened.id != id {
			t.Fatal("remaining destination identity")
		}
	})

	if !bytes.Equal(readAll(t, art), artBytes) || !bytes.Equal(readAll(t, path), source) {
		t.Fatal("publication tests changed the artifact or the source")
	}
}

func incompleteNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "restore-incomplete") {
			names = append(names, entry.Name())
		}
	}
	return names
}

func mustBackup(t *testing.T, src, dir string, pass []byte, logger *log.Logger) (string, Checkpoint) {
	t.Helper()
	src = canonicalExisting(t, src)
	dir = canonicalExisting(t, dir)
	art := filepath.Join(dir, "art-"+randHex(t, 4)+".db")
	cp, err := Backup(src, art, pass, logger)
	if err != nil {
		t.Fatal(err)
	}
	return art, cp
}

func mustUnlock(t *testing.T, path string, pass []byte) *Session {
	t.Helper()
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(opened.Lock)
	return opened
}

func mustReject(t *testing.T, art string, pass []byte, cp Checkpoint, want error) {
	t.Helper()
	dest := filepath.Join(canonicalTemp(t), "dest.db")
	before := readAll(t, art)
	err := Restore(art, dest, pass, cp, nil)
	if !errors.Is(err, want) {
		t.Fatalf("%v", err)
	}
	if _, statErr := os.Lstat(dest); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("destination created")
	}
	if !bytes.Equal(readAll(t, art), before) {
		t.Fatal("rejected restore changed the artifact")
	}
}

func verifyAttest(t *testing.T, env *attestEnv, payload []byte) bool {
	t.Helper()
	att, err := attestErr(t, env, payload)
	if err != nil {
		t.Fatal(err)
	}
	return VerifyLocalAttestation(att.PublicKey[:], env.resource, payload, att.Signature[:])
}

func attestErr(t *testing.T, env *attestEnv, payload []byte) (LocalAttestation, error) {
	t.Helper()
	principal, err := env.s.Agent(env.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	return principal.LocalAttest(LocalAttestRequest{CredentialID: env.cred.ID, Resource: env.resource, Payload: payload})
}

func grantKept(s *Session, grantID string) bool {
	for _, g := range s.grants {
		if g.ID == grantID && g.RevokedAt == nil {
			return true
		}
	}
	return false
}

func assertMode(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
}

func assertNoIncomplete(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "restore-incomplete") {
			t.Fatal(entry.Name())
		}
	}
}

// canonicalTemp is an ordinary temporary directory with symlink components
// resolved. Backup and Restore reject an ancestor symlink, including the
// macOS temporary root /var -> /private/var. A path that still contains a
// symlink is a negative case and must not pass through this helper.
func canonicalTemp(t *testing.T) string {
	t.Helper()
	return canonicalExisting(t, t.TempDir())
}

func canonicalExisting(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func auditReady(t *testing.T, path string) bool {
	t.Helper()
	db, err := openDBRead(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	return auditSchemaReady(db) == nil
}

func auditSeqHash(t *testing.T, path string) string {
	t.Helper()
	db, err := openDBRead(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var hash string
	if err := db.QueryRow(`SELECT hash FROM audit WHERE seq=1`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	return hash
}

func assertNoSecret(t *testing.T, blob, pass, secret []byte) {
	t.Helper()
	if bytes.Contains(blob, pass) || bytes.Contains(blob, secret) {
		t.Fatal("secret bytes in plaintext output")
	}
}
