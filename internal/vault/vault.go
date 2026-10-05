// Package vault is the human control plane for a local encrypted credential store.
//
// Retrieval requires an unlocked session, which requires the vault passphrase.
// This package must not grow an agent-facing raw-secret retrieval API.
package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	formatVersion  = 1
	rootPassphrase = "passphrase"
	algoArgon2id   = "argon2id"

	keyLen   = 32
	saltLen  = 16
	nonceLen = 12

	// RFC 9106 second recommended Argon2id parameter set.
	prodTime    = 3
	prodMemory  = 64 * 1024
	prodThreads = 4

	minPassphrase = 8
	maxPassphrase = 1024
	// MaxSecret is the largest credential payload accepted.
	MaxSecret = 1 << 20
	maxLabel  = 256

	minKDFMemory  = 8 * 1024
	maxKDFMemory  = 1024 * 1024
	maxKDFTime    = 10
	maxKDFThreads = 8

	maxVaultFile = 32 << 20

	// StateActive is the lifecycle state of a newly stored credential.
	StateActive = "active"
)

// CredentialTypes is the allowlist stored with each credential.
var CredentialTypes = []string{
	"password",
	"api_key",
	"bearer_token",
	"oauth",
	"ssh_key",
	"certificate",
	"database",
	"totp",
	"generic",
}

var (
	// ErrUnauthenticated means the passphrase did not unwrap the master key.
	ErrUnauthenticated = errors.New("vault unlock failed")
	// ErrCorrupt means the vault file failed parsing or authentication.
	ErrCorrupt = errors.New("vault data is corrupt or tampered")
	// ErrNotFound means the credential id is not in the unlocked vault.
	ErrNotFound = errors.New("credential not found")
	// ErrInvalid means caller input was rejected.
	ErrInvalid = errors.New("invalid vault input")
	// ErrAudit means the audit chain could not be verified or extended.
	ErrAudit = errors.New("audit log failed verification")
	// ErrIO means a vault file could not be read or written.
	ErrIO = errors.New("vault file operation failed")
	// ErrPassphrase means the CLI has no passphrase source.
	ErrPassphrase = errors.New("passphrase required")
)

// errSidecar means the sealed chain is durable but the append-only mirror write failed.
// Callers must not roll back state that save already committed.
var errSidecar = errors.New("audit sidecar append failed")

// Lifecycle is non-secret metadata stored with a credential.
type Lifecycle struct {
	State         string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	ExpiresAt     *time.Time
	ReviewDueAt   *time.Time
	RotationDueAt *time.Time
}

// Credential is a human-visible credential record.
// Secret is set only by Get on an unlocked session.
type Credential struct {
	ID        string
	Label     string
	Type      string
	Secret    []byte
	Lifecycle Lifecycle
}

// PutOptions carries optional lifecycle times. Zero values mean unset.
type PutOptions struct {
	ExpiresAt     *time.Time
	ReviewDueAt   *time.Time
	RotationDueAt *time.Time
}

type lifecycle struct {
	State         string     `json:"state"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	ReviewDueAt   *time.Time `json:"review_due_at,omitempty"`
	RotationDueAt *time.Time `json:"rotation_due_at,omitempty"`
}

type credential struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Type      string    `json:"type"`
	Secret    []byte    `json:"secret"`
	Lifecycle lifecycle `json:"lifecycle"`
}

type kdfParams struct {
	Algorithm string `json:"algorithm"`
	Salt      []byte `json:"salt"`
	Time      uint32 `json:"time"`
	Memory    uint32 `json:"memory"`
	Threads   uint8  `json:"threads"`
	KeyLen    uint32 `json:"key_len"`
}

type fileHeader struct {
	Version    int       `json:"version"`
	ID         string    `json:"id"`
	Root       string    `json:"root"`
	KDF        kdfParams `json:"kdf"`
	WrapNonce  []byte    `json:"wrap_nonce"`
	WrappedDEK []byte    `json:"wrapped_dek"`
	DataNonce  []byte    `json:"data_nonce"`
	Data       []byte    `json:"data"`
	AuditHead  string    `json:"audit_head"`
	AuditSeq   uint64    `json:"audit_seq"`
}

type document struct {
	Credentials []credential `json:"credentials"`
	Audit       []auditEvent `json:"audit"`
}

// Session is an unlocked vault. Lock zeroes the master key and cached secrets.
type Session struct {
	path     string
	id       string
	dek      []byte
	header   fileHeader
	creds    []credential
	audit    []auditEvent
	redactor *Redactor
	logger   *log.Logger
}

// Create makes a new vault at path and returns it unlocked.
func Create(path string, passphrase []byte, logger *log.Logger) (*Session, error) {
	if err := validatePassphrase(passphrase); err != nil {
		return nil, err
	}
	if err := refuseExisting(path); err != nil {
		return nil, err
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	kdf, err := newKDF()
	if err != nil {
		return nil, err
	}
	kek := deriveKEK(passphrase, kdf)
	defer wipe(kek)
	dek, err := randBytes(keyLen)
	if err != nil {
		return nil, err
	}
	wrapNonce, wrapped, err := seal(kek, dek, dekAAD(id))
	if err != nil {
		wipe(dek)
		return nil, err
	}
	red := &Redactor{}
	red.Add(passphrase)
	s := &Session{
		path: path,
		id:   id,
		dek:  dek,
		header: fileHeader{
			Version:    formatVersion,
			ID:         id,
			Root:       rootPassphrase,
			KDF:        kdf,
			WrapNonce:  wrapNonce,
			WrappedDEK: wrapped,
		},
		creds:    []credential{},
		redactor: red,
		logger:   logger,
	}
	if err := s.persistEvent(actionCreate, "", "", resultAllowed); err != nil {
		s.Lock()
		removeVaultFiles(path)
		if errors.Is(err, errSidecar) {
			return nil, ErrAudit
		}
		return nil, err
	}
	s.logf("vault_create id=%s result=allowed", id)
	return s, nil
}

// Unlock opens path with passphrase. A wrong passphrase appends an unlock denial
// when the audit sidecar can accept one.
func Unlock(path string, passphrase []byte, logger *log.Logger) (*Session, error) {
	if err := validatePassphrase(passphrase); err != nil {
		return nil, err
	}
	header, err := readHeader(path)
	if err != nil {
		return nil, err
	}
	kek := deriveKEK(passphrase, header.KDF)
	defer wipe(kek)
	dek, err := openAEAD(kek, header.WrapNonce, header.WrappedDEK, dekAAD(header.ID))
	if err != nil {
		if aerr := appendUnlockDenial(path, header.ID, header.AuditHead, header.AuditSeq); aerr != nil && !errors.Is(aerr, errNoSidecar) {
			logLine(logger, "vault_unlock result=denied")
			return nil, ErrAudit
		}
		logLine(logger, "vault_unlock result=denied")
		return nil, ErrUnauthenticated
	}
	plain, err := openAEAD(dek, header.DataNonce, header.Data, dataAAD(header.ID, header.AuditHead, header.AuditSeq))
	if err != nil {
		wipe(dek)
		_ = appendUnlockDenial(path, header.ID, header.AuditHead, header.AuditSeq)
		logLine(logger, "vault_unlock result=denied")
		return nil, ErrCorrupt
	}
	defer wipe(plain)
	var doc document
	if err := unmarshalStrict(plain, &doc); err != nil {
		wipe(dek)
		return nil, ErrCorrupt
	}
	if err := validateStored(doc.Credentials); err != nil {
		wipe(dek)
		return nil, err
	}
	if err := verifyChain(doc.Audit); err != nil || len(doc.Audit) == 0 {
		wipe(dek)
		return nil, ErrAudit
	}
	tip := doc.Audit[len(doc.Audit)-1]
	if tip.Hash != header.AuditHead || tip.Seq != header.AuditSeq || tip.VaultID != header.ID {
		wipe(dek)
		return nil, ErrAudit
	}
	side, exists, err := readAudit(auditPath(path))
	if err != nil {
		wipe(dek)
		return nil, err
	}
	merged, err := reconcile(doc.Audit, side, exists)
	if err != nil {
		wipe(dek)
		return nil, err
	}
	red := &Redactor{}
	red.Add(passphrase)
	for i := range doc.Credentials {
		red.Add(doc.Credentials[i].Secret)
	}
	s := &Session{
		path:     path,
		id:       header.ID,
		dek:      dek,
		header:   header,
		creds:    doc.Credentials,
		audit:    merged,
		redactor: red,
		logger:   logger,
	}
	if err := syncSidecar(auditPath(path), merged); err != nil {
		s.Lock()
		return nil, err
	}
	if len(merged) != len(doc.Audit) {
		if err := s.save(); err != nil {
			s.Lock()
			return nil, err
		}
	}
	if err := s.persistEvent(actionUnlock, "", "", resultAllowed); err != nil {
		s.Lock()
		if errors.Is(err, errSidecar) {
			return nil, ErrAudit
		}
		return nil, err
	}
	s.logf("vault_unlock id=%s result=allowed", s.id)
	return s, nil
}

// Lock zeroes the master key and cached secrets. The session cannot be reused.
func (s *Session) Lock() {
	if s == nil {
		return
	}
	wipe(s.dek)
	s.dek = nil
	for i := range s.creds {
		wipe(s.creds[i].Secret)
		s.creds[i].Secret = nil
	}
	s.creds = nil
	s.audit = nil
	if s.redactor != nil {
		s.redactor.Wipe()
	}
}

// Put stores a new credential and returns its metadata. The secret is not echoed.
func (s *Session) Put(label, typ string, secret []byte, opt PutOptions) (Credential, error) {
	if err := s.live(); err != nil {
		return Credential{}, err
	}
	if err := validateLabel(label); err != nil {
		return Credential{}, err
	}
	if err := validateType(typ); err != nil {
		return Credential{}, err
	}
	if err := validateSecret(secret); err != nil {
		return Credential{}, err
	}
	expires, err := optionalTime(opt.ExpiresAt)
	if err != nil {
		return Credential{}, err
	}
	review, err := optionalTime(opt.ReviewDueAt)
	if err != nil {
		return Credential{}, err
	}
	rotation, err := optionalTime(opt.RotationDueAt)
	if err != nil {
		return Credential{}, err
	}
	id, err := newID()
	if err != nil {
		return Credential{}, err
	}
	now := time.Now().UTC()
	rec := credential{
		ID:     id,
		Label:  label,
		Type:   typ,
		Secret: append([]byte(nil), secret...),
		Lifecycle: lifecycle{
			State:         StateActive,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     expires,
			ReviewDueAt:   review,
			RotationDueAt: rotation,
		},
	}
	s.creds = append(s.creds, rec)
	s.redactor.Add(secret)
	if err := s.persistEvent(actionPut, id, typ, resultAllowed); err != nil {
		if !errors.Is(err, errSidecar) {
			wipe(s.creds[len(s.creds)-1].Secret)
			s.creds = s.creds[:len(s.creds)-1]
		}
		if errors.Is(err, errSidecar) {
			return Credential{}, ErrAudit
		}
		return Credential{}, err
	}
	s.logf("credential_put id=%s type=%s label=%s result=allowed", id, typ, label)
	return rec.public(), nil
}

// Get returns one credential, including its secret, after writing an audit event.
// A failed audit does not return the secret.
func (s *Session) Get(id string) (Credential, error) {
	if err := s.live(); err != nil {
		return Credential{}, err
	}
	for i := range s.creds {
		c := &s.creds[i]
		if c.ID != id {
			continue
		}
		if err := s.persistEvent(actionGet, c.ID, c.Type, resultAllowed); err != nil {
			if errors.Is(err, errSidecar) {
				return Credential{}, ErrAudit
			}
			return Credential{}, err
		}
		s.logf("credential_get id=%s type=%s label=%s result=allowed", c.ID, c.Type, c.Label)
		out := c.public()
		out.Secret = append([]byte(nil), c.Secret...)
		return out, nil
	}
	auditedID := safeID(id)
	if s.redactor.Contains([]byte(auditedID)) {
		auditedID = ""
	}
	if err := s.persistEvent(actionGet, auditedID, "", resultDenied); err != nil {
		if errors.Is(err, errSidecar) {
			return Credential{}, ErrAudit
		}
		return Credential{}, err
	}
	s.logf("credential_get id=%s result=denied", auditedID)
	return Credential{}, ErrNotFound
}

// List returns credential metadata. Secrets are omitted.
func (s *Session) List() ([]Credential, error) {
	if err := s.live(); err != nil {
		return nil, err
	}
	if err := s.persistEvent(actionList, "", "", resultAllowed); err != nil {
		if errors.Is(err, errSidecar) {
			return nil, ErrAudit
		}
		return nil, err
	}
	s.logf("credential_list count=%d result=allowed", len(s.creds))
	out := make([]Credential, len(s.creds))
	for i := range s.creds {
		out[i] = s.creds[i].public()
	}
	return out, nil
}

func (c credential) public() Credential {
	return Credential{
		ID:    c.ID,
		Label: c.Label,
		Type:  c.Type,
		Lifecycle: Lifecycle{
			State:         c.Lifecycle.State,
			CreatedAt:     c.Lifecycle.CreatedAt,
			UpdatedAt:     c.Lifecycle.UpdatedAt,
			ExpiresAt:     cloneTime(c.Lifecycle.ExpiresAt),
			ReviewDueAt:   cloneTime(c.Lifecycle.ReviewDueAt),
			RotationDueAt: cloneTime(c.Lifecycle.RotationDueAt),
		},
	}
}

func (s *Session) live() error {
	if s == nil || len(s.dek) != keyLen {
		return ErrUnauthenticated
	}
	return nil
}

func (s *Session) persistEvent(action, credID, credType, result string) error {
	ev, err := nextEvent(s.audit, action, s.id, credID, credType, result)
	if err != nil {
		return err
	}
	s.audit = append(s.audit, ev)
	if err := s.save(); err != nil {
		s.audit = s.audit[:len(s.audit)-1]
		return err
	}
	if err := appendAudit(auditPath(s.path), ev); err != nil {
		return errSidecar
	}
	return nil
}

func (s *Session) save() error {
	if len(s.audit) == 0 || len(s.dek) != keyLen {
		return ErrAudit
	}
	last := s.audit[len(s.audit)-1]
	s.header.Version = formatVersion
	s.header.ID = s.id
	s.header.Root = rootPassphrase
	s.header.AuditHead = last.Hash
	s.header.AuditSeq = last.Seq
	doc := document{Credentials: s.creds, Audit: s.audit}
	plain, err := json.Marshal(doc)
	if err != nil {
		return ErrIO
	}
	defer wipe(plain)
	nonce, ct, err := seal(s.dek, plain, dataAAD(s.id, s.header.AuditHead, s.header.AuditSeq))
	if err != nil {
		return err
	}
	s.header.DataNonce = nonce
	s.header.Data = ct
	raw, err := json.Marshal(s.header)
	if err != nil {
		return ErrIO
	}
	if err := writeAtomic(s.path, raw); err != nil {
		s.logf("io error=%v", err)
		return ErrIO
	}
	return nil
}

func (s *Session) logf(format string, args ...any) {
	if s == nil || s.logger == nil {
		return
	}
	msg := s.redactor.Redact(fmt.Sprintf(format, args...))
	s.logger.Print(msg)
}

func logLine(logger *log.Logger, msg string) {
	if logger != nil {
		logger.Print(msg)
	}
}

func newKDF() (kdfParams, error) {
	salt, err := randBytes(saltLen)
	if err != nil {
		return kdfParams{}, err
	}
	return kdfParams{
		Algorithm: algoArgon2id,
		Salt:      salt,
		Time:      prodTime,
		Memory:    prodMemory,
		Threads:   prodThreads,
		KeyLen:    keyLen,
	}, nil
}

func deriveKEK(passphrase []byte, p kdfParams) []byte {
	return argon2.IDKey(passphrase, p.Salt, p.Time, p.Memory, p.Threads, p.KeyLen)
}

func dekAAD(vaultID string) []byte {
	return []byte("tremelay/v1/dek\x00" + vaultID)
}

func dataAAD(vaultID, auditHead string, auditSeq uint64) []byte {
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], auditSeq)
	return append([]byte("tremelay/v1/data\x00"+vaultID+"\x00"+auditHead+"\x00"), seq[:]...)
}

// seal encrypts with AES-256-GCM.
// ponytail: random 96-bit nonces. Upgrade path: a counter nonce before a vault
// approaches 2^32 seals under one DEK.
func seal(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, ErrIO
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

func openAEAD(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrCorrupt
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrCorrupt
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrCorrupt
	}
	return plain, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Wipe zeroes b. Go may retain other copies.
func Wipe(b []byte) { wipe(b) }

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, ErrIO
	}
	return b, nil
}

func newID() (string, error) {
	b, err := randBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func safeID(id string) string {
	if len(id) != 32 {
		return ""
	}
	if _, err := hex.DecodeString(id); err != nil {
		return ""
	}
	return id
}

func validatePassphrase(p []byte) error {
	if len(p) < minPassphrase || len(p) > maxPassphrase {
		return ErrInvalid
	}
	return nil
}

func validateSecret(s []byte) error {
	if len(s) == 0 || len(s) > MaxSecret {
		return ErrInvalid
	}
	return nil
}

func validateLabel(label string) error {
	if label == "" || len(label) > maxLabel || strings.ContainsAny(label, "\x00\r\n") {
		return ErrInvalid
	}
	return nil
}

func validateType(typ string) error {
	for _, allowed := range CredentialTypes {
		if typ == allowed {
			return nil
		}
	}
	return ErrInvalid
}

func optionalTime(t *time.Time) (*time.Time, error) {
	if t == nil {
		return nil, nil
	}
	if t.IsZero() {
		return nil, ErrInvalid
	}
	u := t.UTC()
	return &u, nil
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil || t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func validateStored(creds []credential) error {
	seen := make(map[string]struct{}, len(creds))
	for _, c := range creds {
		if validateLabel(c.Label) != nil || validateType(c.Type) != nil || validateSecret(c.Secret) != nil {
			return ErrCorrupt
		}
		if safeID(c.ID) == "" {
			return ErrCorrupt
		}
		if _, ok := seen[c.ID]; ok {
			return ErrCorrupt
		}
		seen[c.ID] = struct{}{}
		if c.Lifecycle.State != StateActive || c.Lifecycle.CreatedAt.IsZero() || c.Lifecycle.UpdatedAt.IsZero() {
			return ErrCorrupt
		}
	}
	return nil
}

func validateHeader(h fileHeader) error {
	if h.Version != formatVersion || h.Root != rootPassphrase || safeID(h.ID) == "" {
		return ErrCorrupt
	}
	if h.KDF.Algorithm != algoArgon2id {
		return ErrCorrupt
	}
	if len(h.KDF.Salt) < saltLen || len(h.KDF.Salt) > 64 {
		return ErrCorrupt
	}
	if h.KDF.Time < 1 || h.KDF.Time > maxKDFTime {
		return ErrCorrupt
	}
	if h.KDF.Memory < minKDFMemory || h.KDF.Memory > maxKDFMemory {
		return ErrCorrupt
	}
	if h.KDF.Threads < 1 || h.KDF.Threads > maxKDFThreads {
		return ErrCorrupt
	}
	if h.KDF.KeyLen != keyLen {
		return ErrCorrupt
	}
	if len(h.WrapNonce) != nonceLen || len(h.DataNonce) != nonceLen {
		return ErrCorrupt
	}
	if len(h.WrappedDEK) < keyLen+16 || len(h.Data) < 16 {
		return ErrCorrupt
	}
	if len(h.AuditHead) != 64 || h.AuditSeq == 0 {
		return ErrCorrupt
	}
	if _, err := hex.DecodeString(h.AuditHead); err != nil {
		return ErrCorrupt
	}
	return nil
}

func refuseExisting(path string) error {
	if path == "" {
		return ErrInvalid
	}
	if _, err := os.Stat(path); err == nil {
		return ErrInvalid
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrIO
	}
	if _, err := os.Stat(auditPath(path)); err == nil {
		return ErrInvalid
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrIO
	}
	return nil
}

func readHeader(path string) (fileHeader, error) {
	b, err := readVaultBytes(path)
	if err != nil {
		return fileHeader{}, err
	}
	var header fileHeader
	if err := unmarshalStrict(b, &header); err != nil {
		return fileHeader{}, ErrCorrupt
	}
	if err := validateHeader(header); err != nil {
		return fileHeader{}, err
	}
	return header, nil
}

func readVaultBytes(path string) ([]byte, error) {
	b, err := readLimited(path, maxVaultFile)
	if err == nil {
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	bak, bakErr := readLimited(path+".bak", maxVaultFile)
	if bakErr != nil {
		return nil, ErrInvalid
	}
	return bak, nil
}

func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, ErrIO
	}
	if int64(len(b)) > max {
		return nil, ErrCorrupt
	}
	return b, nil
}

func unmarshalStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return ErrCorrupt
	}
	return nil
}

// writeAtomic replaces path by renaming a synced temp file into place.
// ponytail: single writer. A crash between moving path aside and renaming the
// temp file leaves path.bak. Readers fall back to that file when path is missing.
// Upgrade path: a file lock or SQLite transaction.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tremelay-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	bak := path + ".bak"
	if _, err := os.Stat(path); err == nil {
		os.Remove(bak)
		if err := os.Rename(path, bak); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Rename(bak, path)
		return err
	}
	cleanup = false
	os.Remove(bak)
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

func removeVaultFiles(path string) {
	os.Remove(path)
	os.Remove(path + ".bak")
	os.Remove(auditPath(path))
}
