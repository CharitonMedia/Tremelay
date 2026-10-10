package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"modernc.org/sqlite"
)

const (
	checkpointVersion = "tremelay-checkpoint-v1"
	checkpointMaxText = 512
	copyBuf           = 32 * 1024
	backupStepPages   = 64
)

// restorePublishFault, when set, runs after a staged copy has been validated
// and before the destination name is published. Tests use it. Production
// leaves it nil. The error value is not returned or logged.
var restorePublishFault func() error

// Checkpoint is the host-held binding for one backup artifact.
// Backup returns it. Restore trusts only the value the host passes in.
// Nothing in the artifact, and no file stored next to it, supplies this value.
//
// An old artifact still matches the checkpoint that was issued for that
// artifact. This package cannot tell that pair is stale. The host has to
// pass the checkpoint it currently accepts. A newer checkpoint does not
// match an older artifact, and Restore then refuses.
type Checkpoint struct {
	VaultID  string
	OrgID    string
	AuditSeq uint64
	AuditTip string
	Digest   string
}

// Backup copies srcPath into a new file at artifactPath and returns the
// checkpoint for that file.
//
// The copy uses the pinned SQLite driver's online backup API. The checkpoint
// is taken from the finished artifact, after that API returns and before any
// later audit event on the source: vault id, organization id when the
// snapshot is shared, the audit tip sequence and hash (including a valid
// locked-denial suffix), and the SHA-256 of the artifact bytes. Backup does
// not append an audit event and does not write a manifest.
//
// The host keeps the checkpoint. This call does not freeze other processes
// or machines. The host quiesces writers when the checkpoint must describe
// the newest source state.
func Backup(srcPath, artifactPath string, passphrase []byte, logger *log.Logger) (cp Checkpoint, err error) {
	var created string
	defer func() {
		if err != nil && created != "" {
			os.Remove(created)
			removeSidecars(created)
		}
		logLine(logger, resultLine("vault_backup", err))
	}()
	if err = validatePassphrase(passphrase); err != nil {
		return Checkpoint{}, err
	}
	src, err := cleanPath(srcPath, false)
	if err != nil {
		return Checkpoint{}, err
	}
	dst, err := cleanPath(artifactPath, true)
	if err != nil {
		return Checkpoint{}, err
	}
	if src == dst {
		return Checkpoint{}, ErrInvalid
	}
	f, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return Checkpoint{}, ErrInvalid
		}
		return Checkpoint{}, ErrIO
	}
	if err = f.Close(); err != nil {
		os.Remove(dst)
		return Checkpoint{}, ErrIO
	}
	created = dst
	if err = snapshotDB(src, dst); err != nil {
		return Checkpoint{}, err
	}
	if err = os.Chmod(dst, 0o600); err != nil {
		return Checkpoint{}, ErrIO
	}
	sum, err := fileSHA256(dst)
	if err != nil {
		return Checkpoint{}, err
	}
	view, err := readSnapshot(dst, passphrase)
	if err != nil {
		return Checkpoint{}, err
	}
	again, err := fileSHA256(dst)
	if err != nil {
		return Checkpoint{}, err
	}
	if again != sum {
		return Checkpoint{}, ErrIO
	}
	cp = Checkpoint{VaultID: view.id, OrgID: view.org, AuditSeq: view.seq, AuditTip: view.tip, Digest: sum}
	if err = cp.canonical(); err != nil {
		return Checkpoint{}, ErrCorrupt
	}
	created = ""
	return cp, nil
}

// Restore publishes artifactPath at destPath when passphrase unlocks that
// artifact and want is the checkpoint for it.
//
// destPath must not exist. A symlink component, an existing file, or an
// existing directory is rejected and left unchanged. The artifact is read,
// not written. Validation runs before the destination name is published.
// A failure removes private staging data and does not return a session.
// Restore does not append an audit event. A later Unlock of destPath is an
// ordinary open, including trusted-time expiry.
//
// want is the host's current checkpoint, supplied independently of the
// artifact. A snapshot from before revocation, membership change, request
// consumption, key replacement, or containment does not match a later
// checkpoint. The checkpoint issued for that older snapshot still matches
// it; Restore cannot detect that older pair as stale.
func Restore(artifactPath, destPath string, passphrase []byte, want Checkpoint, logger *log.Logger) (err error) {
	defer func() {
		logLine(logger, resultLine("vault_restore", err))
	}()
	if err = want.canonical(); err != nil {
		return err
	}
	if err = validatePassphrase(passphrase); err != nil {
		return err
	}
	artifact, err := cleanPath(artifactPath, false)
	if err != nil {
		return err
	}
	dest, err := cleanPath(destPath, true)
	if err != nil {
		return err
	}
	if artifact == dest {
		return ErrInvalid
	}
	before, err := fileSHA256(artifact)
	if err != nil {
		return err
	}
	if before != want.Digest {
		return ErrCheckpoint
	}
	view, err := readSnapshot(artifact, passphrase)
	if err != nil {
		return err
	}
	if err = want.matches(view); err != nil {
		return err
	}
	after, err := fileSHA256(artifact)
	if err != nil {
		return err
	}
	if after != before {
		return ErrIO
	}
	return publish(artifact, dest, passphrase, want)
}

func (c Checkpoint) canonical() error {
	if !canonicalID(c.VaultID) || (c.OrgID != "" && !canonicalID(c.OrgID)) {
		return ErrInvalid
	}
	if c.AuditSeq == 0 || !canonicalHexN(c.AuditTip, 64) || !canonicalHexN(c.Digest, 64) {
		return ErrInvalid
	}
	return nil
}

func (c Checkpoint) matches(v snapshotView) error {
	if c.VaultID != v.id || c.OrgID != v.org || c.AuditSeq != v.seq || c.AuditTip != v.tip {
		return ErrCheckpoint
	}
	return nil
}

// MarshalText encodes the checkpoint in the strict host format.
// The encoding is not stored by Backup and is not read back from the artifact.
func (c Checkpoint) MarshalText() ([]byte, error) {
	if err := c.canonical(); err != nil {
		return nil, err
	}
	org := c.OrgID
	if org == "" {
		org = "-"
	}
	text := strings.Join([]string{
		checkpointVersion,
		"vault " + c.VaultID,
		"org " + org,
		"seq " + strconv.FormatUint(c.AuditSeq, 10),
		"tip " + c.AuditTip,
		"sha256 " + c.Digest,
	}, "\n")
	if len(text) > checkpointMaxText {
		return nil, ErrInvalid
	}
	return []byte(text), nil
}

// UnmarshalText parses a checkpoint. Missing, extra, reordered, or malformed
// fields are rejected. Uppercase hex and padded sequence numbers are rejected.
func (c *Checkpoint) UnmarshalText(text []byte) error {
	if c == nil || len(text) == 0 || len(text) > checkpointMaxText {
		return ErrInvalid
	}
	if strings.ContainsRune(string(text), '\r') {
		return ErrInvalid
	}
	body := strings.TrimSuffix(string(text), "\n")
	lines := strings.Split(body, "\n")
	if len(lines) != 6 || lines[0] != checkpointVersion {
		return ErrInvalid
	}
	fields := []string{"vault", "org", "seq", "tip", "sha256"}
	got := map[string]string{}
	for i, key := range fields {
		name, value, ok := strings.Cut(lines[i+1], " ")
		if !ok || name != key || value == "" || strings.Contains(value, " ") {
			return ErrInvalid
		}
		got[key] = value
	}
	org := got["org"]
	if org == "-" {
		org = ""
	}
	seqText := got["seq"]
	seq, err := strconv.ParseUint(seqText, 10, 64)
	if err != nil || strconv.FormatUint(seq, 10) != seqText {
		return ErrInvalid
	}
	parsed := Checkpoint{
		VaultID:  got["vault"],
		OrgID:    org,
		AuditSeq: seq,
		AuditTip: got["tip"],
		Digest:   got["sha256"],
	}
	if err := parsed.canonical(); err != nil {
		return err
	}
	*c = parsed
	return nil
}

type snapshotView struct {
	id  string
	org string
	seq uint64
	tip string
}

// readSnapshot authenticates one artifact without writing it.
// The checks are the unlock checks, without a denial suffix append and
// without a successful-unlock audit row.
func readSnapshot(path string, passphrase []byte) (snapshotView, error) {
	db, header, events, err := loadVaultRead(path)
	if err != nil {
		return snapshotView{}, err
	}
	defer db.Close()
	if err := validatePassphrase(passphrase); err != nil {
		return snapshotView{}, err
	}
	kek := deriveKEK(passphrase, header.KDF)
	defer wipe(kek)
	dek, err := openAEAD(kek, header.WrapNonce, header.WrappedDEK, dekAAD(header.ID))
	if err != nil {
		return snapshotView{}, ErrUnauthenticated
	}
	defer wipe(dek)
	plain, err := openAEAD(dek, header.DataNonce, header.Data, dataAAD(header.ID, header.AuditHead, header.AuditSeq))
	if err != nil {
		return snapshotView{}, ErrCorrupt
	}
	defer wipe(plain)
	var doc document
	defer func() { wipeCredentials(doc.Credentials) }()
	if err := unmarshalStrict(plain, &doc); err != nil {
		return snapshotView{}, ErrCorrupt
	}
	doc.Detection, err = sealedDetection(plain, events, doc.Detection)
	if err != nil {
		return snapshotView{}, err
	}
	if matchDetection(indexFromAudit(events).state(), doc.Detection) != nil {
		return snapshotView{}, ErrCorrupt
	}
	if err := matchHealth(events, doc.Credentials); err != nil {
		return snapshotView{}, err
	}
	if err := validateDocument(doc); err != nil {
		return snapshotView{}, err
	}
	if err := sharedMatchesVault(doc, header.ID); err != nil {
		return snapshotView{}, err
	}
	if err := sharedHistoryBound(events, doc.Organization, doc.Memberships, doc.Requests, doc.Grants); err != nil {
		return snapshotView{}, err
	}
	org := ""
	if doc.Organization != nil {
		org = doc.Organization.ID
	}
	tip := events[len(events)-1]
	if tip.Seq == 0 || tip.VaultID != header.ID || !canonicalHexN(tip.Hash, 64) {
		return snapshotView{}, ErrAudit
	}
	return snapshotView{id: header.ID, org: org, seq: tip.Seq, tip: tip.Hash}, nil
}

type sqliteBackuper interface {
	NewBackup(dstURI string) (*sqlite.Backup, error)
}

func snapshotDB(srcPath, dstPath string) error {
	db, err := openDBRead(srcPath)
	if err != nil {
		return err
	}
	defer db.Close()
	uri, err := sqliteFileURI(dstPath)
	if err != nil {
		return err
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		return ErrIO
	}
	defer conn.Close()
	err = conn.Raw(func(driverConn any) error {
		backuper, ok := driverConn.(sqliteBackuper)
		if !ok {
			return ErrIO
		}
		bk, err := backuper.NewBackup(uri)
		if err != nil {
			return ErrIO
		}
		for {
			more, err := bk.Step(backupStepPages)
			if err != nil {
				_ = bk.Finish()
				return ErrIO
			}
			if !more {
				if err := bk.Finish(); err != nil {
					return ErrIO
				}
				return nil
			}
		}
	})
	if err != nil {
		return ErrIO
	}
	return nil
}

func sqliteFileURI(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", ErrInvalid
	}
	slash := filepath.ToSlash(abs)
	if !strings.HasPrefix(slash, "/") {
		slash = "/" + slash
	}
	q := url.Values{}
	q.Set("mode", "rw")
	return (&url.URL{Scheme: "file", Path: slash, RawQuery: q.Encode()}).String(), nil
}

func publish(artifact, dest string, passphrase []byte, want Checkpoint) error {
	staging, err := createStaging(filepath.Dir(dest))
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			os.Remove(staging)
			removeSidecars(staging)
		}
	}()
	if err := streamCopy(artifact, staging); err != nil {
		return err
	}
	sum, err := fileSHA256(staging)
	if err != nil {
		return err
	}
	if sum != want.Digest {
		return ErrIO
	}
	view, err := readSnapshot(staging, passphrase)
	if err != nil {
		return err
	}
	if err := want.matches(view); err != nil {
		return err
	}
	if restorePublishFault != nil {
		if fault := restorePublishFault(); fault != nil {
			return ErrIO
		}
	}
	if _, err := os.Lstat(dest); err == nil {
		return ErrInvalid
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrIO
	}
	if err := os.Link(staging, dest); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrInvalid
		}
		return ErrIO
	}
	if err := os.Remove(staging); err != nil {
		os.Remove(dest)
		return ErrIO
	}
	if err := os.Chmod(dest, 0o600); err != nil {
		os.Remove(dest)
		return ErrIO
	}
	if err := syncDir(filepath.Dir(dest)); err != nil {
		os.Remove(dest)
		return err
	}
	published = true
	return nil
}

func createStaging(dir string) (string, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	// ponytail: O_EXCL refuses a final symlink, and cleanPath refuses a
	// symlink component beforehand. A parent swapped for a symlink after
	// that walk can still redirect the create. Upgrade path: openat with
	// O_NOFOLLOW on each component.
	path := filepath.Join(dir, "."+id+".restore-incomplete")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", ErrIO
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", ErrIO
	}
	return path, nil
}

func streamCopy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return ErrIO
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY, 0o600)
	if err != nil {
		return ErrIO
	}
	defer out.Close()
	buf := make([]byte, copyBuf)
	if _, err := io.CopyBuffer(out, in, buf); err != nil {
		return ErrIO
	}
	if err := out.Sync(); err != nil {
		return ErrIO
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return ErrIO
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		// Windows directory handles often reject Sync. The file sync above
		// is the data barrier. The directory entry still depends on the OS.
		if runtime.GOOS == "windows" {
			return nil
		}
		return ErrIO
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrInvalid
		}
		return "", ErrIO
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, copyBuf)
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", ErrIO
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func removeSidecars(path string) {
	os.Remove(path + "-journal")
	os.Remove(path + "-wal")
	os.Remove(path + "-shm")
}

func cleanPath(path string, create bool) (string, error) {
	if path == "" || strings.ContainsRune(path, 0) {
		return "", ErrInvalid
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", ErrInvalid
	}
	abs = filepath.Clean(abs)
	if err := walkPath(abs, create); err != nil {
		return "", err
	}
	return abs, nil
}

func walkPath(abs string, create bool) error {
	var chain []string
	cur := abs
	for {
		chain = append(chain, cur)
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	for i := len(chain) - 1; i >= 0; i-- {
		p := chain[i]
		leaf := i == 0
		fi, err := os.Lstat(p)
		if err != nil {
			if leaf && create && errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if errors.Is(err, os.ErrNotExist) {
				return ErrInvalid
			}
			return ErrIO
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return ErrInvalid
		}
		if leaf {
			if create || !fi.Mode().IsRegular() {
				return ErrInvalid
			}
			return nil
		}
		if !fi.IsDir() {
			return ErrInvalid
		}
	}
	return ErrInvalid
}

func canonicalID(id string) bool {
	return canonicalHexN(id, 32) && safeID(id) == id
}

func canonicalHexN(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || (c > '9' && c < 'a') || c > 'f' {
			return false
		}
	}
	return true
}

func resultLine(action string, err error) string {
	if err == nil {
		return action + " result=ok"
	}
	return action + " result=failed"
}
