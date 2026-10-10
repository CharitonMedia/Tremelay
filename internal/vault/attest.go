package vault

import (
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
)

const (
	// OpLocalArtifactAttest authorizes one local Ed25519 attestation.
	// It does not authorize BrokerHTTP, GitHubIssueState, or the sign placeholder.
	OpLocalArtifactAttest = "local_artifact_attest"

	// CredTypeEd25519 is the only credential type this operation will sign with.
	CredTypeEd25519 = "ed25519"

	// AttestDomain is the versioned domain bound into every signed message.
	AttestDomain = "tremelay/local-artifact-attestation/v1"
	// AttestPurpose is the only purpose this operation signs.
	// It is not a caller-supplied label.
	AttestPurpose = "local-artifact-attestation"

	// attestMagic is the fixed prefix of the signed encoding.
	attestMagic = "TREMELAY1"

	// MaxAttestPayload is the largest artifact payload that will be signed.
	MaxAttestPayload = 64 << 10
	// maxAttestKey is the only accepted private-key length.
	// crypto/x509.MarshalPKCS8PrivateKey emits 48 bytes for an Ed25519 key.
	// Longer input is rejected before it is parsed.
	maxAttestKey = 48
)

// LocalAttestRequest is one agent signing call.
// It names a credential, the granted resource, and the artifact payload.
// It has no purpose, algorithm, mode, or key field.
type LocalAttestRequest struct {
	CredentialID string
	Resource     string
	Payload      []byte
}

// LocalAttestation is the public verification result.
// Signature is 64 bytes. PublicKey is 32 bytes. Domain and Purpose are the
// fixed constants. Resource is the granted resource. The payload is not a field.
type LocalAttestation struct {
	Signature [ed25519.SignatureSize]byte `json:"signature"`
	PublicKey [ed25519.PublicKeySize]byte `json:"public_key"`
	Domain    string                      `json:"domain"`
	Purpose   string                      `json:"purpose"`
	Resource  string                      `json:"resource"`
}

// AttestMessage returns the exact bytes this operation signs.
// Domain and purpose are the package constants. A caller cannot select another
// domain, purpose, or signature mode. Verification rebuilds this encoding from
// the expected resource and payload.
func AttestMessage(resource string, payload []byte) ([]byte, error) {
	return attestMessage(AttestDomain, AttestPurpose, resource, payload)
}

// VerifyLocalAttestation reports whether signature is a valid Ed25519 signature
// by publicKey over AttestMessage(resource, payload). A mismatch of key,
// resource, payload, or signature returns false. The function does not accept
// a caller-chosen domain or purpose, and it does not return parser text.
func VerifyLocalAttestation(publicKey []byte, resource string, payload, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	msg, err := AttestMessage(resource, payload)
	if err != nil {
		return false
	}
	defer wipe(msg)
	return ed25519.Verify(ed25519.PublicKey(publicKey), msg, signature)
}

func attestMessage(domain, purpose, resource string, payload []byte) ([]byte, error) {
	if domain == "" || len(domain) > 128 || purpose == "" || len(purpose) > 128 {
		return nil, ErrInvalid
	}
	if err := validateResource(resource); err != nil {
		return nil, err
	}
	if len(payload) == 0 || len(payload) > MaxAttestPayload {
		return nil, ErrInvalid
	}
	out := make([]byte, 0, len(attestMagic)+16+len(domain)+len(purpose)+len(resource)+len(payload))
	out = append(out, attestMagic...)
	out = appendU32(out, len(domain))
	out = append(out, domain...)
	out = appendU32(out, len(purpose))
	out = append(out, purpose...)
	out = appendU32(out, len(resource))
	out = append(out, resource...)
	out = appendU32(out, len(payload))
	out = append(out, payload...)
	return out, nil
}

func appendU32(dst []byte, n int) []byte {
	var u [4]byte
	binary.BigEndian.PutUint32(u[:], uint32(n))
	return append(dst, u[:]...)
}

// parseEd25519Private accepts only the 48-byte PKCS#8 DER that
// crypto/x509.MarshalPKCS8PrivateKey writes for an Ed25519 private key.
// PEM, raw seeds, expanded keys, other algorithms, and non-canonical DER
// are rejected. The error is fixed and does not include the input.
func parseEd25519Private(der []byte) (ed25519.PrivateKey, error) {
	if len(der) != maxAttestKey {
		return nil, ErrSignFailed
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, ErrSignFailed
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(priv) != ed25519.PrivateKeySize {
		return nil, ErrSignFailed
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil || !bytesEqual(canonical, der) {
		wipe(priv)
		return nil, ErrSignFailed
	}
	// Copy so a later wipe of the parsed key cannot alias the caller's buffer.
	out := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(out, priv)
	wipe(priv)
	return out, nil
}

func bytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1 && len(a) == len(b)
}

func attestKeyID(secret []byte) (string, error) {
	priv, err := parseEd25519Private(secret)
	if err != nil {
		return "", ErrInvalid
	}
	defer wipe(priv)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return "", ErrInvalid
	}
	return hex.EncodeToString(pub), nil
}

func canonicalKeyID(id string) bool {
	if len(id) != hex.EncodedLen(ed25519.PublicKeySize) {
		return false
	}
	raw, err := hex.DecodeString(id)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return false
	}
	return hex.EncodeToString(raw) == id
}

func (s *Session) localAttest(agentID string, req LocalAttestRequest) (LocalAttestation, error) {
	if err := s.live(); err != nil {
		return LocalAttestation{}, err
	}
	// Suspension is decided before the payload is inspected, so a suspended
	// agent cannot turn a secret-shaped payload into a different audit result.
	if s.agentExists(agentID) && !s.agentActive(agentID) {
		return s.attestDeny(s.destinationEvent(agentID, req.CredentialID, resultDeniedAgent, OpLocalArtifactAttest), ErrDeniedAgent)
	}
	if len(req.Payload) == 0 || len(req.Payload) > MaxAttestPayload || validateResource(req.Resource) != nil || safeID(req.CredentialID) == "" {
		return s.attestDeny(auditEvent{Result: resultDenied}, ErrInvalid)
	}
	partial, cause := s.judge(agentID, req.CredentialID, OpLocalArtifactAttest, req.Resource)
	if cause != nil {
		return s.attestDeny(partial, cause)
	}
	priv, partial, cause := s.matchAttestKey(partial)
	if cause != nil {
		wipe(priv)
		return s.attestDeny(partial, cause)
	}
	g, ok := s.grantByID(partial.GrantID)
	if !ok || g.Resource != req.Resource {
		wipe(priv)
		partial.Result = resultFailed
		return s.attestDeny(partial, ErrSignFailed)
	}
	msg, err := AttestMessage(g.Resource, req.Payload)
	if err != nil {
		wipe(priv)
		partial.Result = resultFailed
		return s.attestDeny(partial, ErrSignFailed)
	}
	// The allowed row is durable before the private key is used to sign.
	// A failed write here does not sign and does not claim the attempt was recorded.
	if err := s.attestWrite(partial, resultAllowed); err != nil {
		wipe(priv)
		wipe(msg)
		return LocalAttestation{}, err
	}
	if s.attestFault != nil {
		if faultErr := s.attestFault(); faultErr != nil {
			wipe(priv)
			wipe(msg)
			if werr := s.attestWrite(partial, resultFailed); werr != nil {
				return LocalAttestation{}, werr
			}
			return LocalAttestation{}, ErrSignFailed
		}
	}
	sigBytes := ed25519.Sign(priv, msg)
	pub, _ := priv.Public().(ed25519.PublicKey)
	var out LocalAttestation
	copy(out.Signature[:], sigBytes)
	copy(out.PublicKey[:], pub)
	wipe(priv)
	wipe(msg)
	wipe(sigBytes)
	// The completed row is durable before the signature is returned.
	// A failed write discards the signature. The earlier allowed row is not a completion.
	if err := s.attestWrite(partial, resultCompleted); err != nil {
		out = LocalAttestation{}
		return LocalAttestation{}, err
	}
	out.Domain = AttestDomain
	out.Purpose = AttestPurpose
	out.Resource = g.Resource
	return out, nil
}

// matchAttestKey checks the stored key against the grant binding.
// It does not sign. A mismatch or unusable key leaves the private key wiped.
func (s *Session) matchAttestKey(partial auditEvent) (ed25519.PrivateKey, auditEvent, error) {
	g, ok := s.grantByID(partial.GrantID)
	if !ok || g.CredentialClass != "" || g.CredentialID != partial.CredID || !soleLocalAttest(g.Operations) || !canonicalKeyID(g.KeyID) {
		partial.Result = resultFailed
		return nil, partial, ErrSignFailed
	}
	c, ok := s.credByID(partial.CredID)
	if !ok || c.Type != CredTypeEd25519 || c.Lifecycle.State != StateActive {
		partial.Result = resultFailed
		return nil, partial, ErrSignFailed
	}
	secret, ok := s.copySecret(partial.CredID)
	if !ok {
		partial.Result = resultFailed
		return nil, partial, ErrSignFailed
	}
	defer wipe(secret)
	priv, err := parseEd25519Private(secret)
	if err != nil {
		partial.Result = resultFailed
		return nil, partial, ErrSignFailed
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		wipe(priv)
		partial.Result = resultFailed
		return nil, partial, ErrSignFailed
	}
	if keyBound(g.KeyID, pub) {
		return priv, partial, nil
	}
	// decideAccess picks the lowest active grant id before it knows the key.
	// A replaced credential can leave that stale grant active beside a grant
	// for the current key. Choose again from grants that name this public key.
	// Revocation and expiry of those grants still beat a stale active grant.
	// No grant for this key keeps the original id, which is denied_key below.
	partial, cause := s.retargetAttestGrant(partial, g.Resource, pub)
	if cause != nil {
		wipe(priv)
		return nil, partial, cause
	}
	if partial.GrantID == g.ID {
		wipe(priv)
		partial.Result = resultDeniedKey
		return nil, partial, ErrDeniedKey
	}
	ng, ok := s.grantByID(partial.GrantID)
	if !ok || ng.CredentialID != partial.CredID || ng.Resource != g.Resource || !keyBound(ng.KeyID, pub) {
		wipe(priv)
		partial.Result = resultFailed
		return nil, partial, ErrSignFailed
	}
	return priv, partial, nil
}

// retargetAttestGrant moves an allowed decision onto the grant bound to pub.
// An empty match leaves partial unchanged.
func (s *Session) retargetAttestGrant(partial auditEvent, resource string, pub ed25519.PublicKey) (auditEvent, error) {
	matched := grantsForAttestKey(s.grants, partial.AgentID, partial.CredID, resource, hex.EncodeToString(pub))
	if len(matched) == 0 {
		return partial, nil
	}
	now, err := s.evaluationTime()
	if err != nil {
		partial.Result = resultFailed
		return partial, ErrSignFailed
	}
	result, grantID := decideAccess(matched, true, partial.AgentID, partial.CredID, partial.CredType, true, OpLocalArtifactAttest, resource, now)
	if result != resultAllowed {
		partial.Result = result
		partial.GrantID = grantID
		return partial, denialError(result)
	}
	partial.GrantID = grantID
	return partial, nil
}

func grantsForAttestKey(grants []grantRecord, agentID, credID, resource, keyID string) []grantRecord {
	var out []grantRecord
	for _, g := range grants {
		if g.AgentID == agentID && g.CredentialID == credID && g.Resource == resource && g.KeyID == keyID && attestCredScope(g, OpLocalArtifactAttest) {
			out = append(out, g)
		}
	}
	return out
}

func keyBound(keyID string, pub ed25519.PublicKey) bool {
	want, err := hex.DecodeString(keyID)
	return err == nil && len(want) == ed25519.PublicKeySize && subtle.ConstantTimeCompare(want, pub) == 1
}

// screenAttestKey applies the key binding and discards the private key.
// Authorize uses it so a replaced key does not remain an allowed decision.
func (s *Session) screenAttestKey(partial auditEvent) (auditEvent, error) {
	key, ev, err := s.matchAttestKey(partial)
	wipe(key)
	return ev, err
}

func (s *Session) attestWrite(partial auditEvent, result string) error {
	partial.Action = actionLocalAttest
	partial.Result = result
	return s.finish(partial, nil)
}

func (s *Session) attestDeny(partial auditEvent, cause error) (LocalAttestation, error) {
	partial.Action = actionLocalAttest
	if err := s.finish(partial, cause); err != nil {
		return LocalAttestation{}, err
	}
	return LocalAttestation{}, cause
}

func (s *Session) grantByID(id string) (grantRecord, bool) {
	for i := range s.grants {
		if s.grants[i].ID == id {
			return s.grants[i], true
		}
	}
	return grantRecord{}, false
}

func (s *Session) credByID(id string) (credential, bool) {
	for i := range s.creds {
		if s.creds[i].ID == id {
			return s.creds[i], true
		}
	}
	return credential{}, false
}

func soleLocalAttest(ops []string) bool {
	return len(ops) == 1 && ops[0] == OpLocalArtifactAttest
}

func attestGrantOK(ops []string, spec GrantSpec, credType string) error {
	has := false
	for _, op := range ops {
		if op == OpLocalArtifactAttest {
			has = true
		}
	}
	if !has {
		return nil
	}
	if !soleLocalAttest(ops) || spec.CredentialClass != "" || spec.CredentialID == "" || credType != CredTypeEd25519 {
		return ErrInvalid
	}
	return nil
}

func attestCredScope(g grantRecord, op string) bool {
	if op != OpLocalArtifactAttest {
		return true
	}
	return g.CredentialClass == "" && g.CredentialID != "" && soleLocalAttest(g.Operations) && canonicalKeyID(g.KeyID)
}

func validateGrantKey(g grantRecord, types map[string]string) error {
	has := false
	for _, op := range g.Operations {
		if op == OpLocalArtifactAttest {
			has = true
		}
	}
	if !has {
		if g.KeyID != "" {
			return ErrCorrupt
		}
		return nil
	}
	if !soleLocalAttest(g.Operations) || g.CredentialClass != "" || g.CredentialID == "" || types[g.CredentialID] != CredTypeEd25519 || !canonicalKeyID(g.KeyID) {
		return ErrCorrupt
	}
	return nil
}
