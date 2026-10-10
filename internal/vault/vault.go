// Package vault is the human control plane for a local encrypted credential store.
//
// Retrieval requires an unlocked session, which requires the vault passphrase.
// Agent principals and capability grants are a separate authority from that
// human session. AgentPrincipal can list capabilities, authorize them, invoke
// the HTTP broker, request one local Ed25519 attestation, and open one
// host-bound SSH userauth stream for one identity.
// It cannot retrieve credential plaintext. This package must not grow an
// agent-facing raw-secret retrieval API.
package vault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

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

	// StateActive is the lifecycle state of a newly stored credential.
	StateActive = "active"
)

// credentialTypes is the allowlist stored with each credential.
// Other packages see only a copy so they cannot widen Put or store a type
// that validateStored later rejects as corrupt.
var credentialTypes = []string{
	"password",
	"api_key",
	"bearer_token",
	"oauth",
	"ssh_key",
	"certificate",
	"database",
	"totp",
	"generic",
	CredTypeEd25519,
}

// CredentialTypes returns a copy of the credential-type allowlist.
func CredentialTypes() []string {
	return append([]string(nil), credentialTypes...)
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
	// ErrAgentNotFound means the agent id is not a principal in this vault.
	ErrAgentNotFound = errors.New("agent not found")
	// ErrGrantNotFound means the grant id is not in this vault.
	ErrGrantNotFound = errors.New("grant not found")
	// ErrDeniedAgent means authorization failed because the principal does not hold the grant.
	ErrDeniedAgent = errors.New("denied_agent")
	// ErrDeniedCredential means authorization failed because the credential does not match.
	ErrDeniedCredential = errors.New("denied_credential")
	// ErrDeniedOperation means authorization failed because the operation does not match.
	ErrDeniedOperation = errors.New("denied_operation")
	// ErrDeniedScope means authorization failed because the resource scope does not match.
	ErrDeniedScope = errors.New("denied_scope")
	// ErrDeniedExpired means the matching grant is past its expiration.
	ErrDeniedExpired = errors.New("denied_expired")
	// ErrDeniedRevoked means the matching grant has been revoked.
	ErrDeniedRevoked = errors.New("denied_revoked")
	// ErrDeniedMissing means the principal has no capability grant.
	ErrDeniedMissing = errors.New("denied_missing")
	// ErrDeniedDestination means the broker could not confirm a public origin.
	ErrDeniedDestination = errors.New("denied_destination")
	// ErrDeniedOrigin means the request origin is not the granted origin.
	ErrDeniedOrigin = errors.New("denied_origin")
	// ErrDeniedSSRF means the destination is a non-public or special-use address.
	ErrDeniedSSRF = errors.New("denied_ssrf")
	// ErrDeniedRedirect means a redirect was refused instead of forwarding the credential.
	ErrDeniedRedirect = errors.New("denied_redirect")
	// ErrDeniedMethod means the HTTP method is outside the granted method.
	ErrDeniedMethod = errors.New("denied_method")
	// ErrDeniedPath means the path or query is outside the granted resource.
	ErrDeniedPath = errors.New("denied_path")
	// ErrDeniedAction means the request action class is outside the grant.
	ErrDeniedAction = errors.New("denied_action")
	// ErrDeniedMalformed means the target authority is ambiguous or not canonical.
	ErrDeniedMalformed = errors.New("denied_malformed")
	// ErrDeniedAbuse means the abuse-control hook vetoed the call before the credential was sent.
	ErrDeniedAbuse = errors.New("denied_abuse")
	// ErrDeniedDestructive means a configured destructive-method rule refused the call before the credential was sent.
	ErrDeniedDestructive = errors.New("denied_destructive")
	// ErrAuditNotFound means the requested audit sequence is not in the verified chain.
	ErrAuditNotFound = errors.New("audit record not found")
	// ErrBrokerUpstream means the upstream call failed or could not be completed.
	// The error text is fixed and does not include the credential or the URL.
	ErrBrokerUpstream = errors.New("broker upstream failed")
	// ErrDeniedKey means the stored key is not the key identity named by the grant.
	ErrDeniedKey = errors.New("denied_key")
	// ErrSignFailed means a local attestation did not produce a signature.
	// The text is fixed. It does not include key bytes, payloads, or parser output.
	ErrSignFailed = errors.New("signing failed")
	// ErrConflict means a credential changed while it was being evaluated.
	// The in-flight evaluation is discarded. The text is fixed.
	ErrConflict = errors.New("credential changed during evaluation")
)

// Lifecycle is non-secret metadata stored with a credential.
// RotationEvery and ReviewEvery are zero when that interval is disabled.
// An explicit timestamp on the same field takes precedence over the interval.
type Lifecycle struct {
	State         string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	ExpiresAt     *time.Time
	ReviewDueAt   *time.Time
	RotationDueAt *time.Time
	RotationEvery time.Duration
	ReviewEvery   time.Duration
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

// PutOptions carries optional lifecycle times and interval policies.
// A nil time is unset. A zero duration disables that interval.
// Sub-second durations are rejected so a value is not silently truncated.
type PutOptions struct {
	ExpiresAt     *time.Time
	ReviewDueAt   *time.Time
	RotationDueAt *time.Time
	RotationEvery time.Duration
	ReviewEvery   time.Duration
}

type lifecycle struct {
	State         string     `json:"state"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	ReviewDueAt   *time.Time `json:"review_due_at,omitempty"`
	RotationDueAt *time.Time `json:"rotation_due_at,omitempty"`
	// Seconds. Zero is disabled and omitted. Explicit timestamps win.
	RotationEvery int64 `json:"rotation_every,omitempty"`
	ReviewEvery   int64 `json:"review_every,omitempty"`
}

type credential struct {
	ID        string        `json:"id"`
	Label     string        `json:"label"`
	Type      string        `json:"type"`
	Secret    []byte        `json:"secret"`
	Gen       uint64        `json:"gen,omitempty"`
	Lifecycle lifecycle     `json:"lifecycle"`
	Health    *storedHealth `json:"health,omitempty"`
}

type kdfParams struct {
	Algorithm string
	Salt      []byte
	Time      uint32
	Memory    uint32
	Threads   uint8
	KeyLen    uint32
}

type fileHeader struct {
	Version    int
	ID         string
	Root       string
	KDF        kdfParams
	WrapNonce  []byte
	WrappedDEK []byte
	DataNonce  []byte
	Data       []byte
	AuditHead  string
	AuditSeq   uint64
}

// document is the plaintext inside the encrypted blob. Audit history lives
// in the SQLite audit table, not in this document. Agents and grants are
// vault state, not an agent-facing secret channel.
type document struct {
	Credentials []credential  `json:"credentials"`
	Agents      []agentRecord `json:"agents,omitempty"`
	Grants      []grantRecord `json:"grants,omitempty"`
	// Detection is always written, including when empty. A missing member
	// means the document was sealed before M5. See sealedDetection.
	Detection detectionState `json:"detection"`
	// HealthPolicy is absent on vaults sealed before M6. Absence means the
	// documented defaults, not a fabricated healthy assessment.
	HealthPolicy healthPolicy `json:"health_policy,omitempty"`
}

// Session is an unlocked vault. Lock zeroes the master key and cached secrets.
type Session struct {
	path     string
	id       string
	dek      []byte
	header   fileHeader
	creds    []credential
	agents   []agentRecord
	grants   []grantRecord
	audit    []auditEvent
	redactor *Redactor
	logger   *log.Logger
	db       *sql.DB
	// commitFault, when set, fails a credential-state transaction before commit.
	// Tests use it to prove rollback. Production leaves it nil.
	commitFault func() error
	// attestFault, when set, runs after the local-attestation allowed row
	// commits and before Ed25519 signing. A non-nil error withholds the
	// signature. Tests use it. Production leaves it nil.
	attestFault func() error
	// sshFault, when set, runs after the SSH userauth allowed row commits and
	// before Ed25519 signing. A non-nil error withholds the signature.
	// Tests use it. Production leaves it nil.
	sshFault func() error
	// clock, when set, is the trusted time for grant expiry and capability
	// status. Production leaves it nil and uses time.Now. Agent-facing
	// methods cannot set it.
	clock func() time.Time
	// httpDo, when set, sends one already-authorized request. Destination
	// checks run before this hook. Production leaves it nil.
	httpDo func(*http.Request) (*http.Response, error)
	// resolve, when set, answers the broker DNS check. Production leaves it nil.
	resolve func(ctx context.Context, host string) ([]net.IP, error)
	// dial, when set, places the pinned broker connection. Production leaves
	// it nil and uses net.Dialer. The address it receives is the validated pin.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// abuseGuard, when set, can veto an allowed broker call before the
	// credential is copied. It cannot turn a denial into an allow.
	// Production leaves it nil. See ADR 0006.
	abuseGuard func(AbuseDecision) error
	// detection is the encrypted mirror of broker-denial counts. The audit
	// chain is authoritative; a mirror that disagrees fails closed.
	detection detectionState
	// denials is the derived lookback index for detection. Unlock builds it
	// once from the chain. A commit updates it only after that commit
	// succeeds, so a failed write leaves the previous mirror in place.
	denials *detectionIndex
	// notices is per-source response and delivery state. Unlock builds it
	// once from the chain. A commit applies its new rows only after that
	// commit succeeds. It is not part of the encrypted document.
	notices map[uint64]noticeSrc
	// suspensions contains durable containment and explicit-revocation facts.
	suspensions *suspensionIndex
	// notifier delivers high-risk alerts. Nil means delivery is not configured.
	notifier Notifier
	// policy chooses containment. The zero value notifies only and does not
	// mutate grants or agents. See ADR 0007.
	policy ResponsePolicy
	// responding stops a notification or containment row from raising another one.
	responding bool
	// hpolicy is the durable health configuration. The zero value is the
	// documented default. It is sealed with the credential document.
	hpolicy healthPolicy
	// checker is the process-local compromise lookup. Nil means no lookup.
	// It is not sealed, and a new process starts without one. See ADR 0010.
	checker CompromiseChecker
}

// Create makes a new vault at path and returns it unlocked.
func Create(path string, passphrase []byte, logger *log.Logger) (*Session, error) {
	if err := validatePassphrase(passphrase); err != nil {
		return nil, err
	}
	if path == "" {
		return nil, ErrInvalid
	}
	if _, err := os.Stat(path); err == nil {
		return nil, ErrInvalid
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrIO
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
	db, err := createDB(path)
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
		creds:       []credential{},
		notices:     map[uint64]noticeSrc{},
		suspensions: newSuspensionIndex(),
		redactor:    red,
		logger:      logger,
		db:          db,
	}
	if err := s.persistEvent(actionCreate, "", "", resultAllowed); err != nil {
		s.Lock()
		os.Remove(path)
		return nil, err
	}
	s.logf("vault_create id=%s result=allowed", id)
	return s, nil
}

// unlockDecoded, when set, sees credentials after Unlock decodes them and
// before a rejected document is wiped. Tests capture that buffer. Production
// leaves it nil.
var unlockDecoded func([]credential)

// wipedSecret, when set, sees each credential secret immediately before it
// is zeroed. Tests hold that buffer. Production leaves it nil.
var wipedSecret func([]byte)

// Unlock opens path with passphrase. A rejected unlock appends a denial and
// does not update encrypted credential state. The denial has no passphrase
// bytes. A later valid unlock checks that denial suffix and links its own
// event after it.
func Unlock(path string, passphrase []byte, logger *log.Logger) (*Session, error) {
	db, header, events, err := loadVault(path)
	if err != nil {
		return nil, err
	}
	closeDB := true
	defer func() {
		if closeDB {
			db.Close()
		}
	}()
	deny := func(cause error) error {
		if aerr := appendDenial(db, header.ID); aerr != nil {
			logLine(logger, "vault_unlock result=denied")
			return ErrAudit
		}
		logLine(logger, "vault_unlock result=denied")
		return cause
	}
	if err := validatePassphrase(passphrase); err != nil {
		return nil, deny(err)
	}
	kek := deriveKEK(passphrase, header.KDF)
	defer wipe(kek)
	dek, err := openAEAD(kek, header.WrapNonce, header.WrappedDEK, dekAAD(header.ID))
	if err != nil {
		return nil, deny(ErrUnauthenticated)
	}
	plain, err := openAEAD(dek, header.DataNonce, header.Data, dataAAD(header.ID, header.AuditHead, header.AuditSeq))
	if err != nil {
		wipe(dek)
		return nil, deny(ErrCorrupt)
	}
	defer wipe(plain)
	var doc document
	// retained is set only when the session keeps these buffers. Every earlier
	// return, including a partial decode, zeroes them. VerifyAudit does the same.
	retained := false
	defer func() {
		if !retained {
			wipeCredentials(doc.Credentials)
		}
	}()
	if err := unmarshalStrict(plain, &doc); err != nil {
		wipe(dek)
		return nil, deny(ErrCorrupt)
	}
	if unlockDecoded != nil {
		unlockDecoded(doc.Credentials)
	}
	doc.Detection, err = sealedDetection(plain, events, doc.Detection)
	if err != nil {
		wipe(dek)
		return nil, deny(err)
	}
	if err := validateDocument(doc); err != nil {
		wipe(dek)
		return nil, deny(err)
	}
	idx := indexFromAudit(events)
	if err := matchDetection(idx.state(), doc.Detection); err != nil {
		wipe(dek)
		return nil, deny(ErrCorrupt)
	}
	if err := matchHealth(events, doc.Credentials); err != nil {
		wipe(dek)
		return nil, deny(ErrCorrupt)
	}
	red := &Redactor{}
	red.Add(passphrase)
	for i := range doc.Credentials {
		red.Add(doc.Credentials[i].Secret)
	}
	s := &Session{
		path:        path,
		id:          header.ID,
		dek:         dek,
		header:      header,
		creds:       doc.Credentials,
		agents:      doc.Agents,
		grants:      doc.Grants,
		audit:       events,
		detection:   doc.Detection,
		denials:     idx,
		notices:     noticeIndex(events),
		suspensions: suspensionFromAudit(events),
		redactor:    red,
		logger:      logger,
		db:          db,
		hpolicy:     doc.HealthPolicy,
	}
	if err := s.persistEvent(actionUnlock, "", "", resultAllowed); err != nil {
		s.Lock()
		closeDB = false
		return nil, err
	}
	closeDB = false
	s.logf("vault_unlock id=%s result=allowed", s.id)
	retained = true
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
	s.agents = nil
	s.grants = nil
	s.audit = nil
	s.detection = detectionState{}
	s.denials = nil
	s.notices = nil
	s.suspensions = nil
	s.notifier = nil
	s.responding = false
	s.checker = nil
	s.hpolicy = healthPolicy{}
	if s.redactor != nil {
		s.redactor.Wipe()
	}
	if s.db != nil {
		s.db.Close()
		s.db = nil
	}
}

// Put stores a new credential and returns its metadata. The secret is not echoed.
// Invalid input is denied and audited with no secret and no free-form metadata.
func (s *Session) Put(label, typ string, secret []byte, opt PutOptions) (Credential, error) {
	if err := s.live(); err != nil {
		return Credential{}, err
	}
	if err := validateLabel(label); err != nil {
		return s.denyPut(err)
	}
	if err := validateType(typ); err != nil {
		return s.denyPut(err)
	}
	if err := validateSecret(secret); err != nil {
		return s.denyPut(err)
	}
	expires, err := optionalTime(opt.ExpiresAt)
	if err != nil {
		return s.denyPut(err)
	}
	review, err := optionalTime(opt.ReviewDueAt)
	if err != nil {
		return s.denyPut(err)
	}
	rotation, err := optionalTime(opt.RotationDueAt)
	if err != nil {
		return s.denyPut(err)
	}
	rotEvery, err := durationSeconds(opt.RotationEvery)
	if err != nil {
		return s.denyPut(err)
	}
	reviewEvery, err := durationSeconds(opt.ReviewEvery)
	if err != nil {
		return s.denyPut(err)
	}
	id, err := newID()
	if err != nil {
		return Credential{}, err
	}
	now := s.now()
	rec := credential{
		ID:     id,
		Label:  label,
		Type:   typ,
		Gen:    1,
		Secret: append([]byte(nil), secret...),
		Lifecycle: lifecycle{
			State:         StateActive,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     expires,
			ReviewDueAt:   review,
			RotationDueAt: rotation,
			RotationEvery: rotEvery,
			ReviewEvery:   reviewEvery,
		},
	}
	s.redactor.Add(secret)
	stored, err := s.storeNew(rec)
	if err != nil {
		wipe(rec.Secret)
		return Credential{}, err
	}
	return stored, nil
}

// Get returns one credential, including its secret, after committing an audit event.
// A failed audit transaction does not return the secret.
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
			return Credential{}, err
		}
		s.logf("credential_get id=%s type=%s result=allowed", c.ID, c.Type)
		out := c.public()
		out.Secret = append([]byte(nil), c.Secret...)
		return out, nil
	}
	// An unmatched caller-supplied id is not a stored identifier. It may be
	// a foreign secret in credential-id shape, so the denial records none.
	if err := s.persistEvent(actionGet, "", "", resultDenied); err != nil {
		return Credential{}, err
	}
	s.logf("credential_get result=denied")
	return Credential{}, ErrNotFound
}

// List returns credential metadata. Secrets are omitted.
func (s *Session) List() ([]Credential, error) {
	if err := s.live(); err != nil {
		return nil, err
	}
	if err := s.persistEvent(actionList, "", "", resultAllowed); err != nil {
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
			RotationEvery: time.Duration(c.Lifecycle.RotationEvery) * time.Second,
			ReviewEvery:   time.Duration(c.Lifecycle.ReviewEvery) * time.Second,
		},
	}
}

func (s *Session) live() error {
	if s == nil || s.db == nil || len(s.dek) != keyLen {
		return ErrUnauthenticated
	}
	return nil
}

// RejectPut records a secret-free credential_put denial for a write rejected
// before a secret was accepted, such as a secret file that cannot be read.
// Caller input is not stored. A durable denial returns cause; a nil cause is
// treated as ErrInvalid. A failed audit returns that error instead.
func (s *Session) RejectPut(cause error) error {
	return s.denyAction(actionPut, cause)
}

// RejectGet records a metadata-free credential_get denial for a retrieval
// rejected before lookup, such as a malformed invocation. Caller input is
// not stored.
func (s *Session) RejectGet(cause error) error {
	return s.denyAction(actionGet, cause)
}

// RejectList records a metadata-free credential_list denial for a listing
// rejected before it runs. Caller input is not stored.
func (s *Session) RejectList(cause error) error {
	return s.denyAction(actionList, cause)
}

func (s *Session) denyPut(cause error) (Credential, error) {
	return Credential{}, s.denyAction(actionPut, cause)
}

func (s *Session) denyAction(action string, cause error) error {
	if cause == nil {
		cause = ErrInvalid
	}
	if err := s.persistEvent(action, "", "", resultDenied); err != nil {
		return err
	}
	s.logf("%s result=denied", action)
	return cause
}

// failConflict records a fixed denial when a checker commits during evaluation.
// Planned credential state is not written. The checker error is not stored.
func (s *Session) failConflict(action string, err error) error {
	if err == nil || !errors.Is(err, ErrConflict) {
		return err
	}
	if auditErr := s.persistEvent(action, "", "", resultDenied); auditErr != nil {
		return auditErr
	}
	s.logf("%s result=denied", action)
	return ErrConflict
}

func (s *Session) persistEvent(action, credID, credType, result string) error {
	ev, err := nextEvent(s.audit, action, s.id, credID, credType, result)
	if err != nil {
		return err
	}
	return s.commit(ev, s.creds)
}

// commit encrypts credential state under the new audit head and writes that
// ciphertext plus the audit row in one transaction. Agent and grant rows
// already on the session are sealed in the same document. A high-risk row
// also carries its response decision and any configured suspension in that
// same transaction.
func (s *Session) commit(ev auditEvent, creds []credential) error {
	return s.commitState(ev, creds, s.agents, s.grants)
}

func (s *Session) commitState(ev auditEvent, creds []credential, agents []agentRecord, grants []grantRecord) error {
	return s.commitBatch([]auditEvent{ev}, creds, agents, grants, true, nil)
}

// commitBatch seals creds and events in one transaction.
// withResp lets one ordinary security event pick up its M5 response.
// policy, when non-nil, becomes the durable health policy only after commit.
func (s *Session) commitBatch(events []auditEvent, creds []credential, agents []agentRecord, grants []grantRecord, withResp bool, policy *healthPolicy) error {
	if s == nil || s.db == nil || len(s.dek) != keyLen {
		return ErrUnauthenticated
	}
	if len(events) == 0 {
		return ErrAudit
	}
	pol := s.hpolicy
	if policy != nil {
		pol = *policy
	}
	if withResp {
		if len(events) != 1 || noticeAction(events[0].Action) {
			if len(events) != 1 {
				return ErrAudit
			}
		} else {
			var err error
			events, creds, agents, grants, err = s.withResponse(events[0], creds, agents, grants)
			if err != nil {
				return err
			}
		}
	}
	base := s.denials
	if base == nil {
		base = indexFromAudit(s.audit)
	}
	nextDenials := base.clone()
	for _, ev := range events {
		nextDenials.apply(ev)
	}
	det := nextDenials.state()
	if err := validateDetection(det); err != nil {
		return err
	}
	tip := events[len(events)-1]
	plain, err := json.Marshal(document{Credentials: creds, Agents: agents, Grants: grants, Detection: det, HealthPolicy: pol})
	if err != nil {
		return ErrIO
	}
	defer wipe(plain)
	nonce, ct, err := seal(s.dek, plain, dataAAD(s.id, tip.Hash, tip.Seq))
	if err != nil {
		return err
	}
	h := s.header
	h.Version = formatVersion
	h.ID = s.id
	h.Root = rootPassphrase
	h.DataNonce = nonce
	h.Data = ct
	h.AuditHead = tip.Hash
	h.AuditSeq = tip.Seq
	if err := writeTx(s.db, h, events, len(s.audit) == 0, s.commitFault); err != nil {
		if errors.Is(err, ErrIO) {
			s.logf("vault_write result=error")
		}
		return err
	}
	s.header = h
	// Append only after the transaction succeeds. A failed commit leaves the
	// prefix in place, and append grows the backing array instead of copying
	// it on every row. The notice index follows the same commit: a failed
	// write does not publish the rows that were not stored.
	if s.notices == nil {
		s.notices = noticeIndex(s.audit)
	}
	if s.suspensions == nil {
		s.suspensions = suspensionFromAudit(s.audit)
	}
	s.audit = append(s.audit, events...)
	s.creds = creds
	s.agents = agents
	s.grants = grants
	s.detection = det
	s.denials = nextDenials
	s.hpolicy = pol
	for _, row := range events {
		applyNotice(s.notices, row)
		s.suspensions.apply(s.audit, row)
	}
	s.deliverCommitted(events)
	return nil
}

func wipeCredentials(creds []credential) {
	for i := range creds {
		if wipedSecret != nil {
			wipedSecret(creds[i].Secret)
		}
		wipe(creds[i].Secret)
	}
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
	if label == "" || len(label) > maxLabel || strings.ContainsAny(label, "\x00\r\n") || !utf8.ValidString(label) {
		return ErrInvalid
	}
	return nil
}

func validateType(typ string) error {
	for _, allowed := range credentialTypes {
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
	// encoding/json rejects years outside [0,9999]. That failure happens in
	// commit, after validation, and returns ErrIO with no audit event.
	if _, err := u.MarshalJSON(); err != nil {
		return nil, ErrInvalid
	}
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
		if c.Lifecycle.RotationEvery < 0 || c.Lifecycle.ReviewEvery < 0 || c.Lifecycle.RotationEvery > maxPolicySeconds || c.Lifecycle.ReviewEvery > maxPolicySeconds {
			return ErrCorrupt
		}
		if err := validateCredentialHealth(c); err != nil {
			return err
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
