package vault

import (
	"sync"
	"time"
)

// Containment is what a high-risk event may do besides remaining in the audit chain.
// The zero value notifies only and does not mutate a grant or an agent.
type Containment int

const (
	// ContainNotify records the security event and, when a notifier is set, delivers one alert.
	ContainNotify Containment = iota
	// ContainFlag appends a containment row and does not notify or mutate.
	ContainFlag
	// ContainSuspendGrant revokes the grant named on the event, and no other grant.
	ContainSuspendGrant
	// ContainSuspendAgent suspends the agent named on the event, and no other agent.
	ContainSuspendAgent

	// DestructiveOff allows a granted DELETE.
	DestructiveOff = 0
	// DestructiveDeny refuses DELETE before the credential is copied.
	DestructiveDeny = 1
)

// ResponsePolicy is the control-plane choice for high-risk events.
// High zero is ContainNotify. Destructive zero allows a granted DELETE.
type ResponsePolicy struct {
	High        Containment
	Destructive int
}

// Notification is the secret-free alert for one audit row.
// It carries fixed codes and references. It has no URL, header, body, or secret.
type Notification struct {
	Severity     string `json:"severity"`
	Class        string `json:"class"`
	Time         string `json:"time"`
	AgentID      string `json:"agent_id,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	GrantID      string `json:"grant_id,omitempty"`
	Action       string `json:"action"`
	Result       string `json:"result"`
	AuditSeq     uint64 `json:"audit_seq"`
	AuditHash    string `json:"audit_hash"`
}

// Notifier delivers one alert. A non-nil error is a delivery failure.
// The error text is not written to the audit chain or the process log.
type Notifier interface {
	Notify(Notification) error
}

// MemoryNotifier is the deterministic in-process sink used to test delivery.
type MemoryNotifier struct {
	mu    sync.Mutex
	notes []Notification
	err   error
}

// Notify stores n and returns the injected error, if one is set.
func (m *MemoryNotifier) Notify(n Notification) error {
	if m == nil {
		return ErrIO
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notes = append(m.notes, n)
	return m.err
}

// Fail makes later deliveries return err. The error text is not audited.
func (m *MemoryNotifier) Fail(err error) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.err = err
	m.mu.Unlock()
}

// Snapshot returns a copy of the delivered alerts.
func (m *MemoryNotifier) Snapshot() []Notification {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Notification(nil), m.notes...)
}

// SetNotifier installs the alert sink. Nil clears it.
// A nil sink leaves high-risk events audited and does not record a delivery failure.
func (s *Session) SetNotifier(n Notifier) error {
	if err := s.live(); err != nil {
		return err
	}
	s.notifier = n
	return nil
}

// SetResponsePolicy installs containment for later high-risk events.
// It does not rewrite events that are already durable.
func (s *Session) SetResponsePolicy(p ResponsePolicy) error {
	if err := s.live(); err != nil {
		return err
	}
	switch p.High {
	case ContainNotify, ContainFlag, ContainSuspendGrant, ContainSuspendAgent:
	default:
		return ErrInvalid
	}
	if p.Destructive != DestructiveOff && p.Destructive != DestructiveDeny {
		return ErrInvalid
	}
	s.policy = p
	return nil
}

// DeliverPending retries notification for high-risk rows that do not yet
// have a successful delivery. Each source sequence gets at most two attempts,
// and one call sends at most notifyBatch alerts. A delivery error is audited
// as notify/failed and is not returned to the caller.
func (s *Session) DeliverPending() error {
	if err := s.live(); err != nil {
		return err
	}
	if s.notifier == nil || s.responding || s.policy.High == ContainFlag {
		return nil
	}
	s.responding = true
	defer func() { s.responding = false }()
	sent := 0
	for _, ev := range s.audit {
		if sent >= notifyBatch {
			break
		}
		if noticeAction(ev.Action) {
			continue
		}
		class := classify(s.audit, ev)
		if !class.alert() {
			continue
		}
		if notifyDelivered(s.audit, ev.Seq) || notifyAttempts(s.audit, ev.Seq) >= notifyAttemptLimit {
			continue
		}
		if err := s.deliverOne(ev, class); err != nil {
			s.logf("notify seq=%d result=error", ev.Seq)
			return nil
		}
		sent++
	}
	return nil
}

func (s *Session) afterCommit(ev auditEvent) {
	if s == nil || s.responding || noticeAction(ev.Action) {
		return
	}
	class := classify(s.audit, ev)
	if !class.alert() {
		return
	}
	s.responding = true
	defer func() { s.responding = false }()
	if err := s.contain(ev, class); err != nil {
		s.logf("contain seq=%d result=error", ev.Seq)
	}
	if s.policy.High == ContainFlag {
		return
	}
	if err := s.deliverOne(ev, class); err != nil {
		s.logf("notify seq=%d result=error", ev.Seq)
	}
}

func (s *Session) contain(src auditEvent, class Classification) error {
	if contained(s.audit, src.Seq) {
		return nil
	}
	switch s.policy.High {
	case ContainFlag:
		return s.writeNotice(actionContain, resultFlagged, src, class, s.creds, s.agents, s.grants)
	case ContainSuspendGrant:
		return s.containGrant(src, class)
	case ContainSuspendAgent:
		return s.containAgent(src, class)
	default:
		return nil
	}
}

func (s *Session) containGrant(src auditEvent, class Classification) error {
	if safeID(src.GrantID) == "" {
		return s.writeNotice(actionContain, resultFlagged, src, class, s.creds, s.agents, s.grants)
	}
	idx := -1
	for i := range s.grants {
		if s.grants[i].ID == src.GrantID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return s.writeNotice(actionContain, resultFlagged, src, class, s.creds, s.agents, s.grants)
	}
	if s.grants[idx].RevokedAt != nil {
		return s.writeNotice(actionContain, resultUnchanged, src, class, s.creds, s.agents, s.grants)
	}
	next := append([]grantRecord{}, s.grants...)
	revoked := time.Now().UTC()
	next[idx].RevokedAt = &revoked
	return s.writeNotice(actionContain, resultSuspended, src, class, s.creds, s.agents, next)
}

func (s *Session) containAgent(src auditEvent, class Classification) error {
	if safeID(src.AgentID) == "" {
		return s.writeNotice(actionContain, resultFlagged, src, class, s.creds, s.agents, s.grants)
	}
	idx := -1
	for i := range s.agents {
		if s.agents[i].ID == src.AgentID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return s.writeNotice(actionContain, resultFlagged, src, class, s.creds, s.agents, s.grants)
	}
	if s.agents[idx].State == agentStateSuspended {
		return s.writeNotice(actionContain, resultUnchanged, src, class, s.creds, s.agents, s.grants)
	}
	next := append([]agentRecord{}, s.agents...)
	next[idx].State = agentStateSuspended
	return s.writeNotice(actionContain, resultSuspended, src, class, s.creds, next, s.grants)
}

func (s *Session) deliverOne(src auditEvent, class Classification) error {
	if s.notifier == nil {
		return nil
	}
	if notifyDelivered(s.audit, src.Seq) || notifyAttempts(s.audit, src.Seq) >= notifyAttemptLimit {
		return nil
	}
	// The attempt is durable before the sink runs. A crash or a failed outcome
	// write cannot erase it, so DeliverPending cannot exceed notifyAttemptLimit.
	if err := s.writeNotice(actionNotify, resultAttempted, src, class, s.creds, s.agents, s.grants); err != nil {
		return err
	}
	result := resultDelivered
	if err := s.notifier.Notify(notificationFrom(src, class)); err != nil {
		result = resultFailed
	}
	return s.writeNotice(actionNotify, result, src, class, s.creds, s.agents, s.grants)
}

func (s *Session) writeNotice(action, result string, src auditEvent, class Classification, creds []credential, agents []agentRecord, grants []grantRecord) error {
	partial := auditEvent{
		Action:   action,
		Result:   result,
		AgentID:  src.AgentID,
		GrantID:  src.GrantID,
		CredID:   src.CredID,
		CredType: src.CredType,
		Class:    class.Class,
		RefSeq:   src.Seq,
	}
	return s.writeAudit(partial, creds, agents, grants)
}

func notificationFrom(ev auditEvent, class Classification) Notification {
	return Notification{
		Severity:     class.Severity,
		Class:        class.Class,
		Time:         ev.Time,
		AgentID:      ev.AgentID,
		CredentialID: ev.CredID,
		GrantID:      ev.GrantID,
		Action:       ev.Action,
		Result:       ev.Result,
		AuditSeq:     ev.Seq,
		AuditHash:    ev.Hash,
	}
}

func notifyAttempts(events []auditEvent, ref uint64) int {
	n := 0
	for _, ev := range events {
		if ev.Action == actionNotify && ev.RefSeq == ref && ev.Result == resultAttempted {
			n++
		}
	}
	return n
}

func notifyDelivered(events []auditEvent, ref uint64) bool {
	for _, ev := range events {
		if ev.Action == actionNotify && ev.RefSeq == ref && ev.Result == resultDelivered {
			return true
		}
	}
	return false
}

func contained(events []auditEvent, ref uint64) bool {
	for _, ev := range events {
		if ev.Action == actionContain && ev.RefSeq == ref {
			return true
		}
	}
	return false
}
