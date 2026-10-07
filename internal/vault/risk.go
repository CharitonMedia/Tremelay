package vault

import (
	"slices"
	"strings"
	"time"
)

const (
	// SeverityInfo is ordinary allowed activity.
	SeverityInfo = "info"
	// SeverityLow is an ordinary expected denial.
	SeverityLow = "low"
	// SeverityHigh is suspicious behavior an owner should see.
	SeverityHigh = "high"
	// SeverityCritical is tamper, SSRF, or redirect escape.
	SeverityCritical = "critical"

	// ClassRoutine is an ordinary allowed or completed operation.
	ClassRoutine = "routine"
	// ClassExpectedDenial is a deny-by-default result that is not, by itself, suspicious.
	ClassExpectedDenial = "expected_denial"
	// ClassRepeatedDenial is a broker denial pattern past the lookback threshold.
	ClassRepeatedDenial = "repeated_denial"
	// ClassSecretProbe is a closed-set raw-secret retrieval attempt.
	ClassSecretProbe = "secret_probe"
	// ClassOriginMismatch is a destination or origin policy mismatch.
	ClassOriginMismatch = "origin_mismatch"
	// ClassSSRF is a private or special-use destination attempt.
	ClassSSRF = "ssrf"
	// ClassRedirectEscape is a refused redirect.
	ClassRedirectEscape = "redirect_escape"
	// ClassPolicyViolation is a method, path, or action mismatch.
	ClassPolicyViolation = "policy_violation"
	// ClassReplay is use of a revoked broker or authorize capability.
	ClassReplay = "replay"
	// ClassAuditTamper is a failed audit verification. Verify does not append this class.
	ClassAuditTamper = "audit_tamper"
	// ClassRate is the M4 abuse-hook veto.
	ClassRate = "rate"
	// ClassDestructive is a DELETE refused by the destructive-method rule.
	ClassDestructive = "destructive"
	// ClassNotice is a notification or containment row. It does not raise another alert.
	ClassNotice = "notice"

	// ponytail: one counter per agent over the last 32 broker rows, capped at
	// 256 agents. Upgrade path: a time window keyed by grant and credential.
	detectionLookback  = 32
	detectionThreshold = 3
	detectionMaxAgents = 256
	notifyAttemptLimit = 2
	notifyBatch        = 8
	auditPageDefault   = 50
	auditPageMax       = 100
)

// Classification is the stable risk label for one audit row.
type Classification struct {
	Class    string
	Severity string
}

func (c Classification) alert() bool {
	return c.Severity == SeverityHigh || c.Severity == SeverityCritical
}

func knownClass(class string) bool {
	switch class {
	case ClassRoutine, ClassExpectedDenial, ClassRepeatedDenial, ClassSecretProbe,
		ClassOriginMismatch, ClassSSRF, ClassRedirectEscape, ClassPolicyViolation,
		ClassReplay, ClassAuditTamper, ClassRate, ClassDestructive, ClassNotice:
		return true
	default:
		return false
	}
}

func classify(events []auditEvent, ev auditEvent) Classification {
	base := baseClass(ev)
	if base.alert() {
		return base
	}
	if ev.Action == actionBroker && ordinaryBrokerDenial(ev.Result) && safeID(ev.AgentID) != "" {
		if brokerDenialCount(events, ev.AgentID, ev.Seq) >= detectionThreshold {
			return Classification{Class: ClassRepeatedDenial, Severity: SeverityHigh}
		}
	}
	return base
}

func baseClass(ev auditEvent) Classification {
	if noticeAction(ev.Action) {
		return Classification{Class: ClassNotice, Severity: SeverityInfo}
	}
	switch ev.Result {
	case resultAllowed, resultCompleted, resultUpstreamError:
		return Classification{Class: ClassRoutine, Severity: SeverityInfo}
	case resultDeniedSecret:
		return Classification{Class: ClassSecretProbe, Severity: SeverityHigh}
	case resultDeniedOrigin:
		return Classification{Class: ClassOriginMismatch, Severity: SeverityHigh}
	case resultDeniedSSRF:
		return Classification{Class: ClassSSRF, Severity: SeverityCritical}
	case resultDeniedRedirect:
		return Classification{Class: ClassRedirectEscape, Severity: SeverityCritical}
	case resultDeniedMethod, resultDeniedPath, resultDeniedAction:
		return Classification{Class: ClassPolicyViolation, Severity: SeverityHigh}
	case resultDeniedAbuse:
		return Classification{Class: ClassRate, Severity: SeverityHigh}
	case resultDeniedDestructive:
		return Classification{Class: ClassDestructive, Severity: SeverityHigh}
	case resultDeniedRevoked:
		if ev.Action == actionBroker || ev.Action == actionAuthorize {
			return Classification{Class: ClassReplay, Severity: SeverityHigh}
		}
		return Classification{Class: ClassExpectedDenial, Severity: SeverityLow}
	case resultDenied, resultDeniedAgent, resultDeniedCredential, resultDeniedOperation,
		resultDeniedScope, resultDeniedExpired, resultDeniedMissing, resultDeniedDestination,
		resultDeniedMalformed:
		return Classification{Class: ClassExpectedDenial, Severity: SeverityLow}
	default:
		return Classification{Class: ClassAuditTamper, Severity: SeverityCritical}
	}
}

func ordinaryBrokerDenial(result string) bool {
	switch result {
	case resultDenied, resultDeniedAgent, resultDeniedCredential, resultDeniedOperation,
		resultDeniedScope, resultDeniedExpired, resultDeniedMissing, resultDeniedDestination,
		resultDeniedMalformed:
		return true
	default:
		return false
	}
}

func brokerDenialResult(result string) bool {
	switch result {
	case resultAllowed, resultCompleted, resultUpstreamError:
		return false
	default:
		return true
	}
}

func brokerDenialCount(events []auditEvent, agentID string, through uint64) int {
	var rows []auditEvent
	for _, row := range events {
		if row.Seq > through {
			break
		}
		if row.Action == actionBroker && row.AgentID == agentID {
			rows = append(rows, row)
		}
	}
	return countBrokerDenials(rows)
}

func countBrokerDenials(rows []auditEvent) int {
	if len(rows) > detectionLookback {
		rows = rows[len(rows)-detectionLookback:]
	}
	n := 0
	for _, ev := range rows {
		if brokerDenialResult(ev.Result) {
			n++
		}
	}
	return n
}

type detectionState struct {
	Denials []denialSubject `json:"denials,omitempty"`
}

type denialSubject struct {
	AgentID string `json:"agent_id"`
	N       int    `json:"n"`
}

func detectionFromAudit(events []auditEvent) detectionState {
	grouped := map[string][]auditEvent{}
	var order []string
	for _, ev := range events {
		if ev.Action != actionBroker || safeID(ev.AgentID) == "" {
			continue
		}
		if _, ok := grouped[ev.AgentID]; !ok {
			order = append(order, ev.AgentID)
		}
		grouped[ev.AgentID] = append(grouped[ev.AgentID], ev)
	}
	var denials []denialSubject
	for _, id := range order {
		n := countBrokerDenials(grouped[id])
		if n == 0 {
			continue
		}
		denials = append(denials, denialSubject{AgentID: id, N: n})
	}
	slices.SortFunc(denials, func(a, b denialSubject) int {
		return strings.Compare(a.AgentID, b.AgentID)
	})
	return detectionState{Denials: denials}
}

func validateDetection(st detectionState) error {
	if len(st.Denials) > detectionMaxAgents {
		return ErrCorrupt
	}
	prev := ""
	for _, d := range st.Denials {
		if safeID(d.AgentID) == "" || d.AgentID <= prev || d.N < 1 || d.N > detectionLookback {
			return ErrCorrupt
		}
		prev = d.AgentID
	}
	return nil
}

func checkDetection(events []auditEvent, got detectionState) error {
	if err := validateDetection(got); err != nil {
		return err
	}
	want := detectionFromAudit(events)
	if err := validateDetection(want); err != nil {
		return err
	}
	if len(want.Denials) != len(got.Denials) {
		return ErrCorrupt
	}
	for i := range want.Denials {
		if want.Denials[i] != got.Denials[i] {
			return ErrCorrupt
		}
	}
	return nil
}

// AuditRecord is one verified, secret-free audit row plus its risk class.
type AuditRecord struct {
	Seq            uint64 `json:"seq"`
	Time           string `json:"time"`
	Action         string `json:"action"`
	CredentialID   string `json:"credential_id,omitempty"`
	CredentialType string `json:"credential_type,omitempty"`
	Result         string `json:"result"`
	AgentID        string `json:"agent_id,omitempty"`
	GrantID        string `json:"grant_id,omitempty"`
	Operation      string `json:"operation,omitempty"`
	Class          string `json:"class"`
	Severity       string `json:"severity"`
	RefSeq         uint64 `json:"ref_seq,omitempty"`
	Hash           string `json:"hash"`
}

// AuditFilter selects a page of the human audit view.
// AfterSeq is exclusive. Limit defaults to 50 and caps at 100.
// Since and Until bound the event timestamp, inclusive, when non-zero.
type AuditFilter struct {
	CredentialID string
	AgentID      string
	Action       string
	Class        string
	Since        time.Time
	Until        time.Time
	AfterSeq     uint64
	Limit        int
}

// AuditHistory returns a verified page of the audit chain.
// It does not append a row and it does not return credential plaintext.
func (s *Session) AuditHistory(f AuditFilter) ([]AuditRecord, error) {
	if err := s.live(); err != nil {
		return nil, err
	}
	if err := s.verified(); err != nil {
		return nil, err
	}
	limit := f.Limit
	if limit <= 0 {
		limit = auditPageDefault
	}
	if limit > auditPageMax {
		limit = auditPageMax
	}
	var out []AuditRecord
	for _, ev := range s.audit {
		if ev.Seq <= f.AfterSeq {
			continue
		}
		rec := auditRecord(s.audit, ev)
		if f.CredentialID != "" && rec.CredentialID != f.CredentialID {
			continue
		}
		if f.AgentID != "" && rec.AgentID != f.AgentID {
			continue
		}
		if f.Action != "" && rec.Action != f.Action {
			continue
		}
		if f.Class != "" && rec.Class != f.Class {
			continue
		}
		ts, ok := canonicalAuditTime(ev.Time)
		if !ok {
			return nil, ErrAudit
		}
		if !f.Since.IsZero() && ts.Before(f.Since.UTC()) {
			continue
		}
		if !f.Until.IsZero() && ts.After(f.Until.UTC()) {
			continue
		}
		out = append(out, rec)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

// AuditBySeq returns the verified row for seq.
// A non-empty hash that does not match the chain is ErrAudit.
// An unknown sequence is ErrAuditNotFound.
func (s *Session) AuditBySeq(seq uint64, hash string) (AuditRecord, error) {
	if err := s.live(); err != nil {
		return AuditRecord{}, err
	}
	if err := s.verified(); err != nil {
		return AuditRecord{}, err
	}
	if seq == 0 || seq > uint64(len(s.audit)) {
		return AuditRecord{}, ErrAuditNotFound
	}
	ev := s.audit[seq-1]
	if ev.Seq != seq {
		return AuditRecord{}, ErrAudit
	}
	if hash != "" && hash != ev.Hash {
		return AuditRecord{}, ErrAudit
	}
	return auditRecord(s.audit, ev), nil
}

func (s *Session) verified() error {
	if err := verifyChain(s.audit); err != nil {
		return ErrAudit
	}
	if err := checkDetection(s.audit, s.detection); err != nil {
		return ErrAudit
	}
	return nil
}

func auditRecord(events []auditEvent, ev auditEvent) AuditRecord {
	class := classify(events, ev)
	return AuditRecord{
		Seq:            ev.Seq,
		Time:           ev.Time,
		Action:         ev.Action,
		CredentialID:   ev.CredID,
		CredentialType: ev.CredType,
		Result:         ev.Result,
		AgentID:        ev.AgentID,
		GrantID:        ev.GrantID,
		Operation:      ev.Operation,
		Class:          class.Class,
		Severity:       class.Severity,
		RefSeq:         ev.RefSeq,
		Hash:           ev.Hash,
	}
}
