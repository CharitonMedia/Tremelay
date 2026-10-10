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
		OrgID:    strings.Repeat("cd", 16),
		AuditSeq: 12,
		AuditTip: strings.Repeat("ef", 32),
		Digest:   strings.Repeat("ab", 32),
	}
	shared, err := cp.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var got Checkpoint
	if err := got.UnmarshalText(shared); err != nil {
		t.Fatal(err)
	}
	if got != cp {
		t.Fatalf("%+v", got)
	}
	legacy := cp
	legacy.OrgID = ""
	text, err := legacy.MarshalText()
	if err != nil || !bytes.Contains(text, []byte("\norg -\n")) {
		t.Fatalf("%s %v", text, err)
	}
	if err := got.UnmarshalText(append(append([]byte{}, text...), '\n')); err != nil || got != legacy {
		t.Fatalf("%v %+v", err, got)
	}
	body := string(shared)
	bad := []string{
		"",
		"tremelay-checkpoint-v1\n",
		body + "\nextra x",
		strings.Replace(body, "vault ", "id ", 1),
		strings.Replace(body, "sha256 "+cp.Digest, "sha256 "+strings.ToUpper(cp.Digest), 1),
		strings.Replace(body, "\nseq 12\n", "\nseq 01\n", 1),
		strings.Replace(body, "\nseq 12\n", "\nseq 0\n", 1),
		strings.Replace(body, "org "+cp.OrgID, "org -nope", 1),
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
	env := newSharedEnvLog(t, &logBuf)
	spec := env.requestSpec(time.Hour, 30*time.Minute)
	req, err := env.bob.RequestAccess(spec)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := env.alice.Approve(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("m9b-demo-artifact")
	if !verifyAttest(t, env, payload) {
		t.Fatal("source attestation")
	}
	srcHash := readAll(t, env.path)
	dir := t.TempDir()
	art, cp := mustBackup(t, env.path, dir, env.pass, logger)
	if cp.VaultID != env.s.id || cp.OrgID == "" || cp.OrgID != env.s.org.ID || cp.AuditSeq == 0 {
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
	if err := os.WriteFile(art+".manifest", []byte("org stolen\n"), 0o600); err != nil {
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
	if opened.id != env.s.id || opened.org == nil || opened.org.ID != cp.OrgID {
		t.Fatal("restored identity")
	}
	if _, err := opened.Get(env.cred.ID); !errors.Is(err, ErrDenied) {
		t.Fatalf("plaintext %v", err)
	}
	if _, err := opened.IssueGrant(GrantSpec{
		AgentID: env.agent.ID, CredentialID: env.cred.ID,
		Operations: []string{OpLocalArtifactAttest}, Resource: spec.Resource,
		ExpiresAt: time.Now().Add(time.Hour),
	}); !errors.Is(err, ErrDenied) {
		t.Fatalf("direct grant %v", err)
	}
	if !provenanceKept(opened, req.ID, grant.ID) {
		t.Fatal("approval provenance")
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
	alice, err := opened.BindHuman(env.aliceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.RevokeGrant(grant.ID); err != nil {
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
	env := newSharedEnv(t)
	dir := t.TempDir()
	spec := env.requestSpec(time.Hour, 20*time.Minute)
	req, err := env.bob.RequestAccess(spec)
	if err != nil {
		t.Fatal(err)
	}
	artPending, cpPending := mustBackup(t, env.path, dir, env.pass, nil)
	if _, err := env.alice.Approve(req.ID); err != nil {
		t.Fatal(err)
	}
	artApproved, cpApproved := mustBackup(t, env.path, dir, env.pass, nil)
	mustReject(t, artPending, env.pass, cpApproved, ErrCheckpoint)
	// The pending artifact still matches the checkpoint issued for it.
	// That pair is stale against the approved source, and this reference cannot tell.
	pendingDest := filepath.Join(t.TempDir(), "pending.db")
	if err := Restore(artPending, pendingDest, env.pass, cpPending, nil); err != nil {
		t.Fatal(err)
	}
	pending := mustUnlock(t, pendingDest, env.pass)
	if len(pending.requests) != 1 || pending.requests[0].Status != requestPending || len(pending.grants) != 0 {
		t.Fatal("old checkpoint revived a consumed request")
	}
	pending.Lock()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.alice.Replace(env.cred.ID, der, LifecycleOptions{}); err != nil {
		t.Fatal(err)
	}
	artKey, cpKey := mustBackup(t, env.path, dir, env.pass, nil)
	mustReject(t, artApproved, env.pass, cpKey, ErrCheckpoint)
	keyDest := filepath.Join(t.TempDir(), "replaced.db")
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

	if err := env.alice.RevokeGrant(env.s.grants[0].ID); err != nil {
		t.Fatal(err)
	}
	artRevoked, cpRevoked := mustBackup(t, env.path, dir, env.pass, nil)
	mustReject(t, artKey, env.pass, cpRevoked, ErrCheckpoint)
	revokedDest := filepath.Join(t.TempDir(), "revoked.db")
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

	if err := env.alice.Remove(env.bobID); err != nil {
		t.Fatal(err)
	}
	if err := env.alice.Attach(env.bobID, RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := env.alice.AssignRole(env.bobID, RoleOwner); err != nil {
		t.Fatal(err)
	}
	if err := env.alice.AssignRole(env.bobID, RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := env.alice.AssignRole(env.bobID, RoleOwner); err != nil {
		t.Fatal(err)
	}
	_, cpMember := mustBackup(t, env.path, dir, env.pass, nil)
	mustReject(t, artRevoked, env.pass, cpMember, ErrCheckpoint)

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
	containDest := filepath.Join(t.TempDir(), "contained.db")
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

	sameDigest := cpApproved
	sameDigest.AuditSeq++
	mustReject(t, artApproved, env.pass, sameDigest, ErrCheckpoint)
	sameDigest = cpApproved
	sameDigest.AuditTip = strings.Repeat("ab", 32)
	mustReject(t, artApproved, env.pass, sameDigest, ErrCheckpoint)
	sameDigest = cpApproved
	sameDigest.VaultID = strings.Repeat("cd", 16)
	mustReject(t, artApproved, env.pass, sameDigest, ErrCheckpoint)
	sameDigest = cpApproved
	sameDigest.OrgID = ""
	mustReject(t, artApproved, env.pass, sameDigest, ErrCheckpoint)
	missing := cpApproved
	missing.Digest = ""
	mustReject(t, artApproved, env.pass, missing, ErrInvalid)

	wrong := []byte("wrong-passphrase-value")
	artHash := readAll(t, artApproved)
	if err := Restore(artApproved, filepath.Join(t.TempDir(), "nope.db"), wrong, cpApproved, nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
	if !bytes.Equal(readAll(t, artApproved), artHash) {
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
	mustReject(t, bad, env.pass, cpApproved, ErrCheckpoint)
	badSum, err := fileSHA256(bad)
	if err != nil {
		t.Fatal(err)
	}
	badCP := cpApproved
	badCP.Digest = badSum
	dest := filepath.Join(t.TempDir(), "bad-dest.db")
	err = Restore(bad, dest, env.pass, badCP, nil)
	if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrAudit) && !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("corrupt %v", err)
	}
	if _, statErr := os.Lstat(dest); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("corrupt restore published")
	}
	if !bytes.Equal(readAll(t, artApproved), artHash) {
		t.Fatal("corrupt test changed the original artifact")
	}

	occupied := filepath.Join(dir, "occupied.db")
	if err := os.WriteFile(occupied, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Restore(artApproved, occupied, env.pass, cpApproved, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if string(readAll(t, occupied)) != "keep" {
		t.Fatal("destination overwritten")
	}
	if err := Restore(artApproved, env.path, env.pass, cpApproved, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	linkDest := filepath.Join(dir, "alias.db")
	if err := os.Symlink(artApproved, linkDest); err != nil {
		if runtime.GOOS == "windows" {
			t.Log("symlink skipped")
		} else {
			t.Fatal(err)
		}
	} else if err := Restore(artApproved, linkDest, env.pass, cpApproved, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	real := t.TempDir()
	parentLink := filepath.Join(dir, "parent-link")
	if err := os.Symlink(real, parentLink); err == nil {
		if err := Restore(artApproved, filepath.Join(parentLink, "vault.db"), env.pass, cpApproved, nil); !errors.Is(err, ErrInvalid) {
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
	err = Restore(artApproved, faultDest, env.pass, cpApproved, faultLogger)
	if !errors.Is(err, ErrIO) || strings.Contains(err.Error(), "caller-body-sentinel") || strings.Contains(logged.String(), "caller-body-sentinel") {
		t.Fatalf("%v %s", err, logged.String())
	}
	if _, statErr := os.Lstat(faultDest); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("failed publication left a destination")
	}
	assertNoIncomplete(t, dir)
	if !bytes.Equal(readAll(t, artApproved), artHash) {
		t.Fatal("failed publication changed the artifact")
	}
	restorePublishFault = nil
	if err := Restore(artApproved, faultDest, env.pass, cpApproved, nil); err != nil {
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
		art, cp := mustBackup(t, path, t.TempDir(), pass, nil)
		events := mustAudit(t, path)
		tip := events[len(events)-1]
		head := events[len(events)-2]
		if tip.Action != actionUnlock || tip.Result != resultDenied || cp.AuditTip != tip.Hash || cp.AuditSeq != tip.Seq || cp.OrgID != "" {
			t.Fatalf("tip %+v cp %+v", tip, cp)
		}
		if cp.AuditTip == head.Hash {
			t.Fatal("checkpoint ignored the denial suffix")
		}
		forged := cp
		forged.AuditSeq = head.Seq
		forged.AuditTip = head.Hash
		mustReject(t, art, pass, forged, ErrCheckpoint)
		dest := filepath.Join(t.TempDir(), "solo.db")
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
		mustReject(t, art, pass, cpApproved, ErrCheckpoint)
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

func mustBackup(t *testing.T, src, dir string, pass []byte, logger *log.Logger) (string, Checkpoint) {
	t.Helper()
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
	dest := filepath.Join(t.TempDir(), "dest.db")
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

func verifyAttest(t *testing.T, env *sharedEnv, payload []byte) bool {
	t.Helper()
	att, err := attestErr(t, env, payload)
	if err != nil {
		t.Fatal(err)
	}
	return VerifyLocalAttestation(att.PublicKey[:], env.resource, payload, att.Signature[:])
}

func attestErr(t *testing.T, env *sharedEnv, payload []byte) (LocalAttestation, error) {
	t.Helper()
	principal, err := env.s.Agent(env.agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	return principal.LocalAttest(LocalAttestRequest{CredentialID: env.cred.ID, Resource: env.resource, Payload: payload})
}

func provenanceKept(s *Session, requestID, grantID string) bool {
	var grantOK, requestOK bool
	for _, g := range s.grants {
		if g.ID == grantID && g.Provenance != nil && g.Provenance.RequestID == requestID && g.Provenance.RequesterID != g.Provenance.ApproverID {
			grantOK = true
		}
	}
	for _, r := range s.requests {
		if r.ID == requestID && r.Status == requestConsumed && r.GrantID == grantID {
			requestOK = true
		}
	}
	return grantOK && requestOK
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

func assertNoSecret(t *testing.T, blob, pass, secret []byte) {
	t.Helper()
	if bytes.Contains(blob, pass) || bytes.Contains(blob, secret) {
		t.Fatal("secret bytes in plaintext output")
	}
}
