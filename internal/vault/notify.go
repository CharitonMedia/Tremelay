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

// DeliverPending retries notification for high-risk rows whose recorded
// decision is notify and that do not yet have a successful delivery.
// It does not read the current response policy. Each source sequence gets
// at most two attempts, and one call sends at most notifyBatch alerts.
// A delivery error is audited as notify/failed and is not returned to the caller.
func (s *Session) DeliverPending() error {
	if err := s.live(); err != nil {
		return err
	}
	if s.notifier == nil || s.responding {
		return nil
	}
	s.responding = true
	defer func() { s.responding = false }()
	idx := noticeIndex(s.audit)
	sent := 0
	for _, ev := range s.audit {
		if sent >= notifyBatch {
			break
		}
		st, ok := idx[ev.Seq]
		if noticeAction(ev.Action) || !ok || !st.chosen() {
			continue
		}
		class := classifyState(s.audit, ev, s.agents, s.grants)
		if !class.alert() {
			continue
		}
		if st.delivered || st.attempts >= notifyAttemptLimit {
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
	if s == nil || s.responding || noticeAction(ev.Action) || !notifyChosen(s.audit, ev.Seq) {
		return
	}
	class := classifyState(s.audit, ev, s.agents, s.grants)
	if !class.alert() {
		return
	}
	s.responding = true
	defer func() { s.responding = false }()
	if err := s.deliverOne(ev, class); err != nil {
		s.logf("notify seq=%d result=error", ev.Seq)
	}
}

// withResponse appends the authenticated response decision, and any configured
// suspension, to the same commit as ev. Notification transport is not part of
// that commit. A row that is not an alert is returned unchanged.
func (s *Session) withResponse(ev auditEvent, creds []credential, agents []agentRecord, grants []grantRecord) ([]auditEvent, []credential, []agentRecord, []grantRecord, error) {
	class := s.classifyIncoming(ev, agents, grants)
	if !class.alert() {
		return []auditEvent{ev}, creds, agents, grants, nil
	}
	decision := resultDecisionNotify
	if s.policy.High == ContainFlag {
		decision = resultDecisionFlag
	}
	// Hash the response off ev. nextAudit reads only the previous row, so the
	// existing chain is not copied to link these new rows.
	out := []auditEvent{ev}
	var err error
	out, err = appendHashed(out, s.id, noticePartial(actionRespond, decision, ev, class))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	nextAgents, nextGrants, containResult, ok := planContainment(s.policy, ev, agents, grants)
	if ok {
		out, err = appendHashed(out, s.id, noticePartial(actionContain, containResult, ev, class))
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}
	return out, creds, nextAgents, nextGrants, nil
}

func appendHashed(chain []auditEvent, vaultID string, partial auditEvent) ([]auditEvent, error) {
	ev, err := nextAudit(chain, vaultID, partial)
	if err != nil {
		return nil, err
	}
	return append(chain, ev), nil
}

func planContainment(p ResponsePolicy, src auditEvent, agents []agentRecord, grants []grantRecord) ([]agentRecord, []grantRecord, string, bool) {
	switch p.High {
	case ContainFlag:
		return agents, grants, resultFlagged, true
	case ContainSuspendGrant:
		next, result := planSuspendGrant(src, grants)
		return agents, next, result, true
	case ContainSuspendAgent:
		next, result := planSuspendAgent(src, agents)
		return next, grants, result, true
	default:
		return agents, grants, "", false
	}
}

func planSuspendGrant(src auditEvent, grants []grantRecord) ([]grantRecord, string) {
	if safeID(src.GrantID) == "" {
		return grants, resultFlagged
	}
	idx := -1
	for i := range grants {
		if grants[i].ID == src.GrantID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return grants, resultFlagged
	}
	if grants[idx].RevokedAt != nil {
		return grants, resultUnchanged
	}
	next := append([]grantRecord{}, grants...)
	revoked := time.Now().UTC()
	next[idx].RevokedAt = &revoked
	return next, resultSuspended
}

func planSuspendAgent(src auditEvent, agents []agentRecord) ([]agentRecord, string) {
	if safeID(src.AgentID) == "" {
		return agents, resultFlagged
	}
	idx := -1
	for i := range agents {
		if agents[i].ID == src.AgentID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return agents, resultFlagged
	}
	if agents[idx].State == agentStateSuspended {
		return agents, resultUnchanged
	}
	next := append([]agentRecord{}, agents...)
	next[idx].State = agentStateSuspended
	return next, resultAgentSuspended
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

func noticePartial(action, result string, src auditEvent, class Classification) auditEvent {
	return auditEvent{
		Action:   action,
		Result:   result,
		AgentID:  src.AgentID,
		GrantID:  src.GrantID,
		CredID:   src.CredID,
		CredType: src.CredType,
		Class:    class.Class,
		RefSeq:   src.Seq,
	}
}

func (s *Session) writeNotice(action, result string, src auditEvent, class Classification, creds []credential, agents []agentRecord, grants []grantRecord) error {
	return s.writeAudit(noticePartial(action, result, src, class), creds, agents, grants)
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

// noticeIndexVisits counts audit rows read while building one notice index.
// DeliverPending builds that index once per call.
var noticeIndexVisits int

type noticeSrc struct {
	decision  string
	attempts  int
	pending   int
	delivered bool
	hasNotify bool
}

func (st noticeSrc) chosen() bool {
	switch st.decision {
	case resultDecisionNotify:
		return true
	case resultDecisionFlag:
		return false
	}
	return st.hasNotify
}

// noticeIndex is one pass of per-source response and delivery state.
// A respond row is the decision. A source sealed before that decision
// existed is chosen only when a notify row already records delivery.
// Attempt pairing matches notifyAttempts: a legacy outcome with no
// reservation counts, and a modern outcome does not count twice.
func noticeIndex(events []auditEvent) map[uint64]noticeSrc {
	noticeIndexVisits += len(events)
	out := make(map[uint64]noticeSrc, len(events))
	for _, ev := range events {
		if ev.RefSeq == 0 {
			continue
		}
		st := out[ev.RefSeq]
		switch ev.Action {
		case actionRespond:
			if st.decision == "" && (ev.Result == resultDecisionNotify || ev.Result == resultDecisionFlag) {
				st.decision = ev.Result
			}
		case actionNotify:
			st.hasNotify = true
			switch ev.Result {
			case resultAttempted:
				st.attempts++
				st.pending++
			case resultFailed, resultDelivered:
				if st.pending > 0 {
					st.pending--
				} else {
					st.attempts++
				}
				if ev.Result == resultDelivered {
					st.delivered = true
				}
			}
		}
		out[ev.RefSeq] = st
	}
	return out
}

// notifyAttempts counts deliveries for one source. Each attempted row is one
// try. A failed or delivered row with no unmatched attempted row ahead of it
// is a legacy try from before reservations existed. A modern outcome pairs
// with its reservation and is not a second try.
func notifyAttempts(events []auditEvent, ref uint64) int {
	n := 0
	pending := 0
	for _, ev := range events {
		if ev.Action != actionNotify || ev.RefSeq != ref {
			continue
		}
		switch ev.Result {
		case resultAttempted:
			n++
			pending++
		case resultFailed, resultDelivered:
			if pending > 0 {
				pending--
			} else {
				n++
			}
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

// notifyChosen reports whether ref should be delivered. A respond row is the
// decision. A row sealed before that decision existed is delivered only when
// a notify row already records that delivery was chosen. Current session
// policy is not a substitute for either record.
func notifyChosen(events []auditEvent, ref uint64) bool {
	switch responseDecision(events, ref) {
	case resultDecisionNotify:
		return true
	case resultDecisionFlag:
		return false
	}
	for _, ev := range events {
		if ev.Action == actionNotify && ev.RefSeq == ref {
			return true
		}
	}
	return false
}

func responseDecision(events []auditEvent, ref uint64) string {
	for _, ev := range events {
		if ev.Action == actionRespond && ev.RefSeq == ref {
			switch ev.Result {
			case resultDecisionNotify, resultDecisionFlag:
				return ev.Result
			}
		}
	}
	return ""
}
