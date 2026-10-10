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

// ioFault, when set, fails one named Backup or Restore step. Tests use it.
// Production leaves it nil. The error value is not returned or logged.
var ioFault func(step string) error

// ErrPublished means Restore linked the destination and left that name in
// place. A later directory sync or staging cleanup failed, and the
// destination was not removed. The destination is the restored vault.
// Any other error from Restore means the destination name was not left in place.
var ErrPublished = errors.New("vault restore destination remains")

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
//
// srcPath and artifactPath must not contain a symlink component. An ancestor
// symlink is rejected and is not resolved. On macOS the usual temporary
// directory is under /var, which is a symlink to /private/var; pass the
// canonical path.
//
// artifactPath and its SQLite sidecars (journal, wal, shm) must not exist.
// An existing sidecar is left unchanged. The artifact file and its parent
// directory are synced before a checkpoint is returned. If that sync fails,
// the artifact is removed and Backup returns an error.
func Backup(srcPath, artifactPath string, passphrase []byte, logger *log.Logger) (cp Checkpoint, err error) {
	var created string
	var ownSidecars bool
	defer func() {
		if err != nil && created != "" {
			os.Remove(created)
			// A sidecar is removed only after this call has opened the
			// destination. An earlier failure must not delete a recovery
			// file this call did not create.
			if ownSidecars {
				removeSidecars(created)
			}
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
	if err = requireFreshSQLiteName(dst); err != nil {
		return Checkpoint{}, err
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
	opened, err := snapshotDB(src, dst)
	if opened {
		ownSidecars = true
	}
	if err != nil {
		return Checkpoint{}, err
	}
	if err = os.Chmod(dst, 0o600); err != nil {
		return Checkpoint{}, ErrIO
	}
	// Migrate the private artifact before hashing it. A read-only check of
	// the source would reject an M1–M5 audit table, and writing the source
	// would change the vault the host did not ask to upgrade.
	wrote, err := migrateCopiedAudit(dst)
	if wrote {
		ownSidecars = true
	}
	if err != nil {
		return Checkpoint{}, err
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
	if err = syncFile(dst); err != nil || ioFaultStep("backup-sync-file") != nil {
		return Checkpoint{}, ErrIO
	}
	if err = syncDir(filepath.Dir(dst)); err != nil || ioFaultStep("backup-sync-dir") != nil {
		return Checkpoint{}, ErrIO
	}
	created = ""
	return cp, nil
}

// Restore publishes artifactPath at destPath when passphrase unlocks that
// artifact and want is the checkpoint for it.
//
// destPath must not exist, and neither may its SQLite journal, wal, or shm
// sidecar. An existing sidecar is left unchanged. A symlink component,
// including an ancestor, an existing file, or an existing directory is
// rejected and left unchanged. The path is not resolved. The artifact is
// read, not written. Validation, mode 0600, and the sidecar check run before
// the destination name is published.
//
// The link is the commit. ErrPublished means destPath remains after a later
// directory sync or staging cleanup failed. Any other error means destPath
// was not left in place. A failure before the link removes private staging
// data. Restore does not return a session or append an audit event. A later
// Unlock of destPath is an ordinary open, including trusted-time expiry.
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

// migrateCopiedAudit upgrades a private backup artifact when its audit
// table predates the current columns. A current schema is not opened for
// write, so those bytes stay the online-backup image. Existing row hashes
// are not rewritten. The caller hashes the artifact after this returns.
func migrateCopiedAudit(path string) (wrote bool, err error) {
	db, err := openDBRead(path)
	if err != nil {
		return false, err
	}
	ready := auditSchemaReady(db)
	closeErr := db.Close()
	if ready == nil {
		if closeErr != nil {
			return false, ErrIO
		}
		return false, nil
	}
	if closeErr != nil {
		return false, ErrIO
	}
	// openDB may create a journal before it returns. The caller owns
	// sidecars from this point, including when the open fails.
	wrote = true
	db, err = openDB(path)
	if err != nil {
		return true, err
	}
	err = migrateAudit(db)
	closeErr = db.Close()
	if err != nil {
		return true, err
	}
	if closeErr != nil {
		return true, ErrIO
	}
	removeSidecars(path)
	return true, nil
}

func snapshotDB(srcPath, dstPath string) (destOpened bool, err error) {
	db, err := openDBRead(srcPath)
	if err != nil {
		return false, err
	}
	defer db.Close()
	uri, err := sqliteFileURI(dstPath)
	if err != nil {
		return false, err
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		return false, ErrIO
	}
	defer conn.Close()
	err = conn.Raw(func(driverConn any) error {
		backuper, ok := driverConn.(sqliteBackuper)
		if !ok {
			return ErrIO
		}
		// NewBackup opens the destination and may create a sidecar.
		destOpened = true
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
		return destOpened, ErrIO
	}
	return destOpened, nil
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
	// Mode is on the inode the link will share. A failure here is still
	// before the destination name exists.
	if ioFaultStep("chmod") != nil || os.Chmod(staging, 0o600) != nil {
		return ErrIO
	}
	if err := requireFreshSQLiteName(dest); err != nil {
		return err
	}
	if err := os.Link(staging, dest); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrInvalid
		}
		return ErrIO
	}
	// The destination name is committed. Later steps must not report
	// absence while this name remains.
	published = true
	return finishPublish(staging, dest)
}

// finishPublish syncs the destination directory, then drops the staging name.
// It runs only after the link. ErrIO means the destination was removed.
// ErrPublished means the destination remains.
func finishPublish(staging, dest string) error {
	if err := syncDir(filepath.Dir(dest)); err != nil || ioFaultStep("sync") != nil {
		if ioFaultStep("rollback") != nil || os.Remove(dest) != nil {
			// The destination name is still there. Dropping the staging
			// link is cleanup; it does not make this absence.
			os.Remove(staging)
			removeSidecars(staging)
			return ErrPublished
		}
		os.Remove(staging)
		removeSidecars(staging)
		_ = syncDir(filepath.Dir(dest))
		return ErrIO
	}
	if ioFaultStep("unlink") != nil || os.Remove(staging) != nil {
		return ErrPublished
	}
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

func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return ErrIO
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
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
	for _, name := range sqliteSidecars(path) {
		os.Remove(name)
	}
}

func sqliteSidecars(path string) []string {
	return []string{path + "-journal", path + "-wal", path + "-shm"}
}

// requireFreshSQLiteName rejects path and its rollback or WAL sidecars.
// It does not create, modify, or delete any of them.
//
// ponytail: the check and the later create or link are not one directory
// operation. A sidecar that appears after this returns can still sit beside
// the new name. Upgrade path: exclusive-create each sidecar before the
// database file is published.
func requireFreshSQLiteName(path string) error {
	names := append([]string{path}, sqliteSidecars(path)...)
	for _, name := range names {
		_, err := os.Lstat(name)
		if err == nil {
			return ErrInvalid
		}
		if !errors.Is(err, os.ErrNotExist) {
			return ErrIO
		}
	}
	return nil
}

func ioFaultStep(step string) error {
	if ioFault == nil {
		return nil
	}
	return ioFault(step)
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

// walkPath rejects a symlink at any component, including an ancestor.
// The host supplies a canonical path. Resolving the link would follow an alias.
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
