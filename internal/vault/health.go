package vault

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// ReasonWeak means the password matched the strength heuristic.
	ReasonWeak = "weak"
	// ReasonReused means the same password bytes are stored on another credential.
	ReasonReused = "reused"
	// ReasonCompromised means the configured checker confirmed a match.
	ReasonCompromised = "compromised"
	// ReasonExpired means the explicit expiry instant has been reached.
	ReasonExpired = "expired"
	// ReasonReviewDue means the review instant, including reminder lead, has been reached.
	ReasonReviewDue = "review_due"
	// ReasonRotationDue means the rotation instant is inside the reminder window and not yet due.
	ReasonRotationDue = "rotation_due"
	// ReasonRotationOverdue means the rotation instant has been reached.
	ReasonRotationOverdue = "rotation_overdue"

	// CompromiseMatch is a confirmed checker match for this credential generation.
	CompromiseMatch = "match"
	// CompromiseClear means that checker returned no match at that time.
	// It is not proof the credential is safe.
	CompromiseClear = "clear"
	// CompromiseNotChecked means no lookup was configured or opted in.
	CompromiseNotChecked = "not_checked"
	// CompromiseUnavailable means the checker failed, timed out, or returned a malformed body.
	CompromiseUnavailable = "unavailable"
	// CompromiseStale means a completed negative check is older than the freshness window.
	// A confirmed match is not rewritten to stale.
	CompromiseStale = "stale"

	// StrengthWeak means the heuristic found a predictable password.
	StrengthWeak = "weak"
	// StrengthAcceptable means the scanned password did not match the heuristic.
	StrengthAcceptable = "acceptable"
	// StrengthUnassessed means the password was longer than the scan bound.
	StrengthUnassessed = "unassessed"
	// StrengthUnsupported means this credential type has no password heuristic.
	StrengthUnsupported = "unsupported"

	// EvidenceUnassessed means this vault has no assessment for the credential.
	EvidenceUnassessed = "unassessed"
	// EvidencePartial means at least one applicable check did not complete.
	EvidencePartial = "partial"
	// EvidenceComplete means every applicable check finished.
	// It does not mean the credential is safe.
	EvidenceComplete = "complete"

	unknownIssuer   = "unsupported_issuer"
	unknownKey      = "unsupported_key"
	unknownFormat   = "unsupported_format"
	unknownStrength = "strength_bounded"

	defaultMinLength    = 12
	defaultPatternRun   = 6
	defaultFreshness    = 24 * time.Hour
	defaultReminderLead = 7 * 24 * time.Hour
	// strengthScanMax bounds the bytes the heuristic reads.
	// Longer secrets are stored whole and reported unassessed.
	strengthScanMax = 8192
	// compromisePrefixHex is the SHA-256 hex prefix a checker may see.
	compromisePrefixHex = 5
	maxSuffixes         = 1024
	maxPolicySeconds    = 10 * 365 * 24 * 3600
)

// CompromiseQuery is the only input a checker receives.
// Prefix is compromisePrefixHex lowercase hex characters of SHA-256(secret).
// The password, the full hash, the credential id, and the vault id are not included.
type CompromiseQuery struct {
	Algorithm string
	Prefix    string
}

// CompromiseChecker is a process-local lookup. A nil checker performs no lookup.
// Lookup returns the remaining lowercase hex of compromised SHA-256 hashes that
// share Prefix. An empty slice and a nil error is a completed negative check.
// The error text is discarded.
type CompromiseChecker interface {
	Lookup(CompromiseQuery) ([]string, error)
}

// Health is the secret-free assessment shown to the human control plane.
type Health struct {
	CredentialID  string    `json:"credential_id"`
	Type          string    `json:"type"`
	SecretVersion uint64    `json:"secret_version,omitempty"`
	AssessedAt    time.Time `json:"assessed_at,omitempty"`
	Fresh         bool      `json:"fresh"`
	Findings      []string  `json:"findings,omitempty"`
	Unknown       []string  `json:"unknown,omitempty"`
	Compromise    string    `json:"compromise"`
	Strength      string    `json:"strength"`
	Evidence      string    `json:"evidence"`
}

// HealthPolicy is the durable assessment configuration.
// Zero MinPasswordLength, PatternRun, and Freshness mean the documented defaults.
// ReminderLead is explicit, including zero for no early reminder.
type HealthPolicy struct {
	MinPasswordLength int           `json:"min_password_length"`
	PatternRun        int           `json:"pattern_run"`
	Freshness         time.Duration `json:"freshness"`
	ReminderLead      time.Duration `json:"reminder_lead"`
	CompromiseOptIn   bool          `json:"compromise_opt_in"`
}

// LifecycleOptions changes lifecycle policy without changing credential type.
// A nil duration leaves that interval unchanged. A zero duration disables it.
// A clear flag and a replacement timestamp for the same field are rejected.
type LifecycleOptions struct {
	ExpiresAt     *time.Time
	ClearExpires  bool
	ReviewDueAt   *time.Time
	ClearReview   bool
	RotationDueAt *time.Time
	ClearRotation bool
	RotationEvery *time.Duration
	ReviewEvery   *time.Duration
}

type healthPolicy struct {
	MinPasswordLength int    `json:"min_password_length,omitempty"`
	PatternRun        int    `json:"pattern_run,omitempty"`
	FreshnessSec      int64  `json:"freshness_sec,omitempty"`
	ReminderLeadSec   *int64 `json:"reminder_lead_sec,omitempty"`
	CompromiseOptIn   bool   `json:"compromise_opt_in,omitempty"`
}

type storedHealth struct {
	Gen        uint64    `json:"gen"`
	At         time.Time `json:"at"`
	Findings   []string  `json:"findings,omitempty"`
	Unknown    []string  `json:"unknown,omitempty"`
	Compromise string    `json:"compromise"`
	Strength   string    `json:"strength"`
}

type resolvedPolicy struct {
	Min   int
	Run   int
	Fresh time.Duration
	Lead  time.Duration
	OptIn bool
}

type plannedRow struct {
	partial auditEvent
	notify  bool
}

func (s *Session) now() time.Time {
	if s != nil && s.clock != nil {
		return s.clock().UTC()
	}
	return time.Now().UTC()
}

// DefaultHealthPolicy returns the resolved defaults, including the reminder lead.
func DefaultHealthPolicy() HealthPolicy {
	return (healthPolicy{}).resolve().public()
}

func (p healthPolicy) resolve() resolvedPolicy {
	r := resolvedPolicy{
		Min:   defaultMinLength,
		Run:   defaultPatternRun,
		Fresh: defaultFreshness,
		Lead:  defaultReminderLead,
		OptIn: p.CompromiseOptIn,
	}
	if p.MinPasswordLength != 0 {
		r.Min = p.MinPasswordLength
	}
	if p.PatternRun != 0 {
		r.Run = p.PatternRun
	}
	if p.FreshnessSec != 0 {
		r.Fresh = time.Duration(p.FreshnessSec) * time.Second
	}
	if p.ReminderLeadSec != nil {
		r.Lead = time.Duration(*p.ReminderLeadSec) * time.Second
	}
	return r
}

func (r resolvedPolicy) public() HealthPolicy {
	return HealthPolicy{
		MinPasswordLength: r.Min,
		PatternRun:        r.Run,
		Freshness:         r.Fresh,
		ReminderLead:      r.Lead,
		CompromiseOptIn:   r.OptIn,
	}
}

func policyFromPublic(p HealthPolicy) (healthPolicy, error) {
	stored := healthPolicy{
		MinPasswordLength: p.MinPasswordLength,
		PatternRun:        p.PatternRun,
		CompromiseOptIn:   p.CompromiseOptIn,
	}
	if p.Freshness != 0 {
		sec, err := durationSeconds(p.Freshness)
		if err != nil || sec == 0 {
			return healthPolicy{}, ErrInvalid
		}
		stored.FreshnessSec = sec
	}
	sec, err := durationSeconds(p.ReminderLead)
	if err != nil {
		return healthPolicy{}, err
	}
	stored.ReminderLeadSec = &sec
	if err := policyRanges(stored); err != nil {
		return healthPolicy{}, err
	}
	return stored, nil
}

func policyRanges(p healthPolicy) error {
	if p.MinPasswordLength != 0 && (p.MinPasswordLength < 8 || p.MinPasswordLength > 128) {
		return ErrInvalid
	}
	if p.PatternRun != 0 && (p.PatternRun < 3 || p.PatternRun > 64) {
		return ErrInvalid
	}
	if p.FreshnessSec != 0 && (p.FreshnessSec < 1 || p.FreshnessSec > maxPolicySeconds) {
		return ErrInvalid
	}
	if p.ReminderLeadSec != nil && (*p.ReminderLeadSec < 0 || *p.ReminderLeadSec > maxPolicySeconds) {
		return ErrInvalid
	}
	return nil
}

func validateHealthPolicyStored(p healthPolicy) error {
	if policyRanges(p) != nil {
		return ErrCorrupt
	}
	return nil
}

func durationSeconds(d time.Duration) (int64, error) {
	if d < 0 || d%time.Second != 0 {
		return 0, ErrInvalid
	}
	sec := int64(d / time.Second)
	if sec > maxPolicySeconds {
		return 0, ErrInvalid
	}
	return sec, nil
}

// SetCompromiseChecker installs the process-local lookup. Nil clears it.
// A lookup runs only when health policy has opted in. The checker is not
// written into the vault.
func (s *Session) SetCompromiseChecker(c CompromiseChecker) error {
	if err := s.live(); err != nil {
		return err
	}
	s.checker = c
	return nil
}

// SetHealthPolicy persists thresholds and reevaluates current credentials.
// Containment policy is not consulted. A failed commit leaves the previous policy.
func (s *Session) SetHealthPolicy(p HealthPolicy) error {
	if err := s.live(); err != nil {
		return err
	}
	stored, err := policyFromPublic(p)
	if err != nil {
		return s.denyAction(actionHealthPolicy, err)
	}
	next := cloneCreds(s.creds)
	rows := []plannedRow{{partial: auditEvent{Action: actionHealthPolicy, Result: resultAllowed}}}
	assessed, err := s.planAssess(next, credIDs(next), actionHealth, "", &stored)
	if err != nil {
		return s.failConflict(actionHealthPolicy, err)
	}
	return s.commitPlans(append(rows, assessed...), next, &stored)
}

// Health returns one secret-free assessment. It does not reevaluate.
func (s *Session) Health(id string) (Health, error) {
	if err := s.live(); err != nil {
		return Health{}, err
	}
	if safeID(id) == "" {
		return Health{}, s.denyAction(actionHealthGet, ErrInvalid)
	}
	for i := range s.creds {
		if s.creds[i].ID != id {
			continue
		}
		if err := s.persistEvent(actionHealthGet, id, s.creds[i].Type, resultAllowed); err != nil {
			return Health{}, err
		}
		s.logf("health_get id=%s result=allowed", id)
		return s.present(s.creds[i]), nil
	}
	if err := s.persistEvent(actionHealthGet, "", "", resultDenied); err != nil {
		return Health{}, err
	}
	s.logf("health_get result=denied")
	return Health{}, ErrNotFound
}

// ListHealth returns every assessment and the resolved policy.
func (s *Session) ListHealth() ([]Health, HealthPolicy, error) {
	if err := s.live(); err != nil {
		return nil, HealthPolicy{}, err
	}
	if err := s.persistEvent(actionHealthList, "", "", resultAllowed); err != nil {
		return nil, HealthPolicy{}, err
	}
	out := make([]Health, len(s.creds))
	for i := range s.creds {
		out[i] = s.present(s.creds[i])
	}
	s.logf("health_list count=%d result=allowed", len(out))
	return out, s.hpolicy.resolve().public(), nil
}

// RefreshHealth reevaluates one credential, or every credential when id is empty.
// It uses the session clock. There is no background schedule.
func (s *Session) RefreshHealth(id string) error {
	if err := s.live(); err != nil {
		return err
	}
	if id != "" && safeID(id) == "" {
		return s.denyAction(actionRefresh, ErrInvalid)
	}
	next := cloneCreds(s.creds)
	var ids []string
	always := ""
	if id == "" {
		ids = credIDs(next)
	} else if credIndex(next, id) < 0 {
		return s.denyAction(actionRefresh, ErrNotFound)
	} else {
		ids = []string{id}
		always = id
	}
	rows, err := s.planAssess(next, ids, actionRefresh, always, nil)
	if err != nil {
		return s.failConflict(actionRefresh, err)
	}
	if len(rows) == 0 {
		rows = []plannedRow{{partial: auditEvent{Action: actionRefresh, Result: resultUnchanged}}}
	}
	return s.commitPlans(rows, next, nil)
}

// Replace stores a new secret for an existing credential.
// The id, type, creation time, and grants stay in place.
func (s *Session) Replace(id string, secret []byte, opt LifecycleOptions) (Credential, error) {
	if err := s.live(); err != nil {
		return Credential{}, err
	}
	if safeID(id) == "" || validateSecret(secret) != nil {
		return Credential{}, s.denyAction(actionReplace, ErrInvalid)
	}
	next := cloneCreds(s.creds)
	i := credIndex(next, id)
	if i < 0 {
		return Credential{}, s.denyAction(actionReplace, ErrNotFound)
	}
	lc, err := applyLifecycle(next[i].Lifecycle, opt)
	if err != nil {
		return Credential{}, s.denyAction(actionReplace, err)
	}
	old := next[i].Secret
	same := subtle.ConstantTimeCompare(old, secret) == 1
	fresh := append([]byte(nil), secret...)
	next[i].Secret = fresh
	next[i].Lifecycle = lc
	// Generation and UpdatedAt move only when the secret bytes change, so a
	// known compromise for those bytes survives a later checker failure.
	if next[i].Gen == 0 || !same {
		next[i].Lifecycle.UpdatedAt = s.now()
		if next[i].Gen == 0 {
			next[i].Gen = 1
		} else {
			next[i].Gen++
		}
	}
	s.redactor.Add(secret)
	rows, err := s.rowsForChange(next, id, actionReplace, actionHealth)
	if err != nil {
		wipe(fresh)
		return Credential{}, s.failConflict(actionReplace, err)
	}
	if err := s.commitPlans(rows, next, nil); err != nil {
		wipe(fresh)
		return Credential{}, err
	}
	wipe(old)
	return next[i].public(), nil
}

// SetLifecycle updates lifecycle policy for one credential and reevaluates it.
// The secret, type, id, and creation time stay in place.
func (s *Session) SetLifecycle(id string, opt LifecycleOptions) (Credential, error) {
	if err := s.live(); err != nil {
		return Credential{}, err
	}
	if safeID(id) == "" || !lifecycleTouched(opt) {
		return Credential{}, s.denyAction(actionLifecycle, ErrInvalid)
	}
	next := cloneCreds(s.creds)
	i := credIndex(next, id)
	if i < 0 {
		return Credential{}, s.denyAction(actionLifecycle, ErrNotFound)
	}
	lc, err := applyLifecycle(next[i].Lifecycle, opt)
	if err != nil {
		return Credential{}, s.denyAction(actionLifecycle, err)
	}
	next[i].Lifecycle = lc
	if next[i].Gen == 0 {
		next[i].Gen = 1
	}
	rows, err := s.rowsForChange(next, id, actionLifecycle, actionHealth)
	if err != nil {
		return Credential{}, s.failConflict(actionLifecycle, err)
	}
	if err := s.commitPlans(rows, next, nil); err != nil {
		return Credential{}, err
	}
	return next[i].public(), nil
}

// RejectReplace records a secret-free replacement denial.
func (s *Session) RejectReplace(cause error) error {
	return s.denyAction(actionReplace, cause)
}

// RejectLifecycle records a secret-free lifecycle denial.
func (s *Session) RejectLifecycle(cause error) error {
	return s.denyAction(actionLifecycle, cause)
}

// RejectHealth records a secret-free health-read denial.
func (s *Session) RejectHealth(cause error) error {
	return s.denyAction(actionHealthGet, cause)
}

// RejectRefresh records a secret-free refresh denial.
func (s *Session) RejectRefresh(cause error) error {
	return s.denyAction(actionRefresh, cause)
}

// RejectHealthPolicy records a secret-free policy denial.
func (s *Session) RejectHealthPolicy(cause error) error {
	return s.denyAction(actionHealthPolicy, cause)
}

func (s *Session) storeNew(rec credential) (Credential, error) {
	next := append(cloneCreds(s.creds), rec)
	rows, err := s.rowsForChange(next, rec.ID, actionPut, actionHealth)
	if err != nil {
		return Credential{}, s.failConflict(actionPut, err)
	}
	if err := s.commitPlans(rows, next, nil); err != nil {
		return Credential{}, err
	}
	return next[len(next)-1].public(), nil
}

func (s *Session) rowsForChange(next []credential, id, op, assessAction string) ([]plannedRow, error) {
	i := credIndex(next, id)
	if i < 0 {
		return nil, ErrNotFound
	}
	ids := []string{id}
	if next[i].Type == "password" {
		ids = append(ids, reuseChanged(s.creds, next)...)
	}
	rows := []plannedRow{{partial: auditEvent{
		Action:   op,
		Result:   resultAllowed,
		CredID:   id,
		CredType: next[i].Type,
		CredGen:  next[i].Gen,
	}}}
	if op == actionPut {
		rows[0].partial.CredGen = 0
	}
	assessed, err := s.planAssess(next, uniqueIDs(ids), assessAction, id, nil)
	if err != nil {
		return nil, err
	}
	return append(rows, assessed...), nil
}

// planAssess fills health on next for ids. alwaysID always gets a row.
// Other ids get a row only when findings change. The session is not modified.
func (s *Session) planAssess(next []credential, ids []string, action, alwaysID string, policy *healthPolicy) ([]plannedRow, error) {
	now := s.now()
	pol := s.hpolicy.resolve()
	if policy != nil {
		pol = policy.resolve()
	}
	reuse := reuseSet(next)
	oldHealth := map[string]*storedHealth{}
	oldGen := map[string]uint64{}
	for i := range s.creds {
		oldHealth[s.creds[i].ID] = s.creds[i].Health
		oldGen[s.creds[i].ID] = s.creds[i].Gen
	}
	var rows []plannedRow
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		i := credIndex(next, id)
		if i < 0 {
			return nil, ErrNotFound
		}
		if next[i].Gen == 0 {
			next[i].Gen = 1
		}
		var prev *storedHealth
		if oldGen[id] == next[i].Gen {
			prev = oldHealth[id]
		}
		h, err := s.assessCredential(next[i], reuse[id], prev, now, pol)
		if err != nil {
			return nil, err
		}
		next[i].Health = &h
		changed := oldHealth[id] == nil || oldGen[id] != next[i].Gen || !sameFindings(oldHealth[id], h.Findings)
		if id != alwaysID && !changed {
			continue
		}
		result := resultAllowed
		if !changed {
			result = resultUnchanged
		}
		notify := false
		if oldGen[id] != next[i].Gen {
			notify = len(h.Findings) > 0
		} else {
			notify = addedFinding(oldHealth[id], h.Findings)
		}
		rows = append(rows, plannedRow{
			notify: notify,
			partial: auditEvent{
				Action:   action,
				Result:   result,
				CredID:   id,
				CredType: next[i].Type,
				Reasons:  joinReasons(h.Findings),
				CredGen:  next[i].Gen,
			},
		})
	}
	return rows, nil
}

func (s *Session) commitPlans(rows []plannedRow, creds []credential, policy *healthPolicy) error {
	if len(rows) == 0 {
		return ErrAudit
	}
	var events []auditEvent
	for _, row := range rows {
		chain := make([]auditEvent, len(s.audit)+len(events))
		copy(chain, s.audit)
		copy(chain[len(s.audit):], events)
		ev, err := nextAudit(chain, s.id, row.partial)
		if err != nil {
			return err
		}
		events = append(events, ev)
		if !row.notify {
			continue
		}
		chain = make([]auditEvent, len(s.audit)+len(events))
		copy(chain, s.audit)
		copy(chain[len(s.audit):], events)
		resp, err := nextAudit(chain, s.id, noticePartial(actionRespond, resultDecisionNotify, ev, Classification{Class: ClassHealth, Severity: SeverityHigh}))
		if err != nil {
			return err
		}
		events = append(events, resp)
	}
	if err := s.commitBatch(events, creds, s.agents, s.grants, false, policy); err != nil {
		return err
	}
	for _, ev := range events {
		if noticeAction(ev.Action) {
			continue
		}
		s.logf("%s id=%s type=%s result=%s reasons=%s", ev.Action, ev.CredID, ev.CredType, ev.Result, ev.Reasons)
	}
	return nil
}

func (s *Session) assessCredential(c credential, reused bool, prev *storedHealth, now time.Time, pol resolvedPolicy) (storedHealth, error) {
	h := storedHealth{
		Gen:        c.Gen,
		At:         now,
		Strength:   StrengthUnsupported,
		Compromise: CompromiseNotChecked,
	}
	if c.Type == "password" {
		strength, unknown := assessPassword(c.Secret, pol)
		h.Strength = strength
		h.Unknown = unknown
		if strength == StrengthWeak {
			h.Findings = append(h.Findings, ReasonWeak)
		}
		if reused {
			h.Findings = append(h.Findings, ReasonReused)
		}
		comp, err := s.checkCompromise(c, prev, pol)
		if err != nil {
			return storedHealth{}, err
		}
		h.Compromise = comp
		if comp == CompromiseMatch {
			h.Findings = append(h.Findings, ReasonCompromised)
		}
	} else {
		h.Unknown = []string{unknownFormat, unknownIssuer, unknownKey}
	}
	h.Findings = append(h.Findings, lifecycleFindings(c, pol, now)...)
	slices.Sort(h.Findings)
	h.Findings = slices.Compact(h.Findings)
	slices.Sort(h.Unknown)
	h.Unknown = slices.Compact(h.Unknown)
	return h, nil
}

func (s *Session) checkCompromise(c credential, prev *storedHealth, pol resolvedPolicy) (string, error) {
	keepMatch := prev != nil && prev.Gen == c.Gen && prev.Compromise == CompromiseMatch
	if !pol.OptIn || s.checker == nil {
		if keepMatch {
			return CompromiseMatch, nil
		}
		return CompromiseNotChecked, nil
	}
	prefix, suffix := splitHash(c.Secret)
	seq := s.header.AuditSeq
	suffixes, err := s.checker.Lookup(CompromiseQuery{Algorithm: "sha256", Prefix: prefix})
	if s.header.AuditSeq != seq {
		return "", ErrConflict
	}
	if err != nil || !validSuffixes(suffixes) {
		if keepMatch {
			return CompromiseMatch, nil
		}
		return CompromiseUnavailable, nil
	}
	want := []byte(suffix)
	for _, got := range suffixes {
		if subtle.ConstantTimeCompare([]byte(got), want) == 1 {
			return CompromiseMatch, nil
		}
	}
	return CompromiseClear, nil
}

func (s *Session) present(c credential) Health {
	out := Health{
		CredentialID: c.ID,
		Type:         c.Type,
		Evidence:     EvidenceUnassessed,
		Compromise:   CompromiseNotChecked,
		Strength:     StrengthUnsupported,
	}
	if c.Health == nil || c.Gen == 0 {
		return out
	}
	h := c.Health
	pol := s.hpolicy.resolve()
	fresh := !h.At.IsZero() && !s.now().After(h.At.Add(pol.Fresh))
	comp := h.Compromise
	if comp == CompromiseClear && !fresh {
		comp = CompromiseStale
	}
	out.SecretVersion = c.Gen
	out.AssessedAt = h.At
	out.Fresh = fresh
	out.Findings = append([]string(nil), h.Findings...)
	out.Unknown = append([]string(nil), h.Unknown...)
	out.Compromise = comp
	out.Strength = h.Strength
	out.Evidence = evidenceOf(c.Type, h, comp)
	return out
}

func evidenceOf(typ string, h *storedHealth, shown string) string {
	if h == nil || h.At.IsZero() || len(h.Unknown) > 0 {
		return EvidencePartial
	}
	if typ == "password" {
		if h.Strength != StrengthWeak && h.Strength != StrengthAcceptable {
			return EvidencePartial
		}
		if shown == CompromiseMatch || shown == CompromiseClear {
			return EvidenceComplete
		}
		return EvidencePartial
	}
	return EvidencePartial
}

func lifecycleFindings(c credential, pol resolvedPolicy, now time.Time) []string {
	var out []string
	if c.Lifecycle.ExpiresAt != nil && !now.Before(c.Lifecycle.ExpiresAt.UTC()) {
		out = append(out, ReasonExpired)
	}
	if due, ok := reviewDue(c); ok && !now.Before(due.Add(-pol.Lead)) {
		out = append(out, ReasonReviewDue)
	}
	if due, ok := rotationDue(c); ok {
		if !now.Before(due) {
			out = append(out, ReasonRotationOverdue)
		} else if pol.Lead > 0 && !now.Before(due.Add(-pol.Lead)) {
			out = append(out, ReasonRotationDue)
		}
	}
	return out
}

func reviewDue(c credential) (time.Time, bool) {
	if c.Lifecycle.ReviewDueAt != nil {
		return c.Lifecycle.ReviewDueAt.UTC(), true
	}
	if c.Lifecycle.ReviewEvery > 0 {
		return c.Lifecycle.CreatedAt.Add(time.Duration(c.Lifecycle.ReviewEvery) * time.Second), true
	}
	return time.Time{}, false
}

func rotationDue(c credential) (time.Time, bool) {
	if c.Lifecycle.RotationDueAt != nil {
		return c.Lifecycle.RotationDueAt.UTC(), true
	}
	if c.Lifecycle.RotationEvery > 0 {
		return c.Lifecycle.UpdatedAt.Add(time.Duration(c.Lifecycle.RotationEvery) * time.Second), true
	}
	return time.Time{}, false
}

func applyLifecycle(lc lifecycle, opt LifecycleOptions) (lifecycle, error) {
	if (opt.ClearExpires && opt.ExpiresAt != nil) || (opt.ClearReview && opt.ReviewDueAt != nil) || (opt.ClearRotation && opt.RotationDueAt != nil) {
		return lc, ErrInvalid
	}
	if opt.ClearExpires {
		lc.ExpiresAt = nil
	}
	if opt.ExpiresAt != nil {
		t, err := optionalTime(opt.ExpiresAt)
		if err != nil {
			return lc, err
		}
		lc.ExpiresAt = t
	}
	if opt.ClearReview {
		lc.ReviewDueAt = nil
	}
	if opt.ReviewDueAt != nil {
		t, err := optionalTime(opt.ReviewDueAt)
		if err != nil {
			return lc, err
		}
		lc.ReviewDueAt = t
	}
	if opt.ClearRotation {
		lc.RotationDueAt = nil
	}
	if opt.RotationDueAt != nil {
		t, err := optionalTime(opt.RotationDueAt)
		if err != nil {
			return lc, err
		}
		lc.RotationDueAt = t
	}
	if opt.RotationEvery != nil {
		sec, err := durationSeconds(*opt.RotationEvery)
		if err != nil {
			return lc, err
		}
		lc.RotationEvery = sec
	}
	if opt.ReviewEvery != nil {
		sec, err := durationSeconds(*opt.ReviewEvery)
		if err != nil {
			return lc, err
		}
		lc.ReviewEvery = sec
	}
	return lc, nil
}

func lifecycleTouched(opt LifecycleOptions) bool {
	return opt.ExpiresAt != nil || opt.ClearExpires || opt.ReviewDueAt != nil || opt.ClearReview ||
		opt.RotationDueAt != nil || opt.ClearRotation || opt.RotationEvery != nil || opt.ReviewEvery != nil
}

func splitHash(secret []byte) (prefix, suffix string) {
	sum := sha256.Sum256(secret)
	encoded := hex.EncodeToString(sum[:])
	return encoded[:compromisePrefixHex], encoded[compromisePrefixHex:]
}

func validSuffixes(list []string) bool {
	if len(list) > maxSuffixes {
		return false
	}
	want := sha256.Size*2 - compromisePrefixHex
	for _, s := range list {
		if len(s) != want || !lowerHex(s) {
			return false
		}
	}
	return true
}

func lowerHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func canonicalReasons(s string) bool {
	if s == "" {
		return true
	}
	return canonicalList(strings.Split(s, ","), knownReason)
}

func knownReason(s string) bool {
	switch s {
	case ReasonWeak, ReasonReused, ReasonCompromised, ReasonExpired, ReasonReviewDue, ReasonRotationDue, ReasonRotationOverdue:
		return true
	default:
		return false
	}
}

func knownUnknown(s string) bool {
	switch s {
	case unknownIssuer, unknownKey, unknownFormat, unknownStrength:
		return true
	default:
		return false
	}
}

func knownCompromise(s string) bool {
	switch s {
	case CompromiseMatch, CompromiseClear, CompromiseNotChecked, CompromiseUnavailable:
		return true
	default:
		return false
	}
}

func knownStrength(s string) bool {
	switch s {
	case StrengthWeak, StrengthAcceptable, StrengthUnassessed, StrengthUnsupported:
		return true
	default:
		return false
	}
}

func canonicalList(list []string, ok func(string) bool) bool {
	prev := ""
	for _, p := range list {
		if !ok(p) || p <= prev {
			return false
		}
		prev = p
	}
	return true
}

func joinReasons(f []string) string {
	return strings.Join(f, ",")
}

func sameFindings(old *storedHealth, next []string) bool {
	var cur []string
	if old != nil {
		cur = old.Findings
	}
	if len(cur) != len(next) {
		return false
	}
	for i := range cur {
		if cur[i] != next[i] {
			return false
		}
	}
	return true
}

func addedFinding(old *storedHealth, next []string) bool {
	have := map[string]bool{}
	if old != nil {
		for _, f := range old.Findings {
			have[f] = true
		}
	}
	for _, f := range next {
		if !have[f] {
			return true
		}
	}
	return false
}

func validateCredentialHealth(c credential) error {
	if c.Gen == 0 {
		if c.Health != nil {
			return ErrCorrupt
		}
		return nil
	}
	h := c.Health
	if h == nil || h.Gen != c.Gen || h.At.IsZero() || !knownCompromise(h.Compromise) || !knownStrength(h.Strength) {
		return ErrCorrupt
	}
	if !canonicalList(h.Findings, knownReason) || !canonicalList(h.Unknown, knownUnknown) {
		return ErrCorrupt
	}
	return nil
}

// matchHealth binds stored findings to the latest health row for that credential.
// A legacy credential has neither a row nor an assessment.
func matchHealth(events []auditEvent, creds []credential) error {
	latest := map[string]auditEvent{}
	for _, ev := range events {
		if ev.Action != actionHealth && ev.Action != actionRefresh {
			continue
		}
		if ev.CredID == "" || (ev.Result != resultAllowed && ev.Result != resultUnchanged) {
			continue
		}
		latest[ev.CredID] = ev
	}
	seen := map[string]bool{}
	for _, c := range creds {
		seen[c.ID] = true
		ev, ok := latest[c.ID]
		if !ok {
			if c.Health != nil || c.Gen != 0 {
				return ErrCorrupt
			}
			continue
		}
		if c.Health == nil || c.Gen != ev.CredGen || joinReasons(c.Health.Findings) != ev.Reasons {
			return ErrCorrupt
		}
	}
	for id := range latest {
		if !seen[id] {
			return ErrCorrupt
		}
	}
	return nil
}

func cloneCreds(in []credential) []credential {
	out := make([]credential, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].Lifecycle.ExpiresAt = cloneTime(in[i].Lifecycle.ExpiresAt)
		out[i].Lifecycle.ReviewDueAt = cloneTime(in[i].Lifecycle.ReviewDueAt)
		out[i].Lifecycle.RotationDueAt = cloneTime(in[i].Lifecycle.RotationDueAt)
		out[i].Health = cloneHealth(in[i].Health)
	}
	return out
}

func cloneHealth(h *storedHealth) *storedHealth {
	if h == nil {
		return nil
	}
	cp := *h
	cp.Findings = append([]string(nil), h.Findings...)
	cp.Unknown = append([]string(nil), h.Unknown...)
	return &cp
}

func credIndex(creds []credential, id string) int {
	for i := range creds {
		if creds[i].ID == id {
			return i
		}
	}
	return -1
}

func credIDs(creds []credential) []string {
	out := make([]string, len(creds))
	for i := range creds {
		out[i] = creds[i].ID
	}
	return out
}

func uniqueIDs(ids []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// reuseSet reports password ids that share bytes with a different password.
// ponytail: pairwise compare, O(n^2) in the password count, bounded by MaxSecret.
// Upgrade path: a session-only HMAC map wiped on Lock and never sealed.
func reuseSet(creds []credential) map[string]bool {
	var idx []int
	for i := range creds {
		if creds[i].Type == "password" {
			idx = append(idx, i)
		}
	}
	out := map[string]bool{}
	for a := 0; a < len(idx); a++ {
		for b := a + 1; b < len(idx); b++ {
			i, j := idx[a], idx[b]
			if sameSecret(creds[i].Secret, creds[j].Secret) {
				out[creds[i].ID] = true
				out[creds[j].ID] = true
			}
		}
	}
	return out
}

func reuseChanged(old, next []credential) []string {
	a := reuseSet(old)
	b := reuseSet(next)
	seen := map[string]struct{}{}
	for id := range a {
		seen[id] = struct{}{}
	}
	for id := range b {
		seen[id] = struct{}{}
	}
	var out []string
	for id := range seen {
		if a[id] != b[id] {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

func sameSecret(a, b []byte) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

var commonExact = map[string]struct{}{}

func init() {
	for _, w := range commonPasswords {
		commonExact[w] = struct{}{}
	}
}

// commonPasswords is a small embedded exact list. It is not a breach corpus
// and it is not a general dictionary. Matching is case-folded for ASCII only
// at check time; the stored bytes are not rewritten.
var commonPasswords = []string{
	"password", "password1", "password123", "123456", "12345678", "123456789",
	"1234567890", "qwerty", "qwerty123", "abc123", "letmein", "admin", "welcome",
	"iloveyou", "monkey", "dragon", "master", "login", "passw0rd", "trustno1",
	"sunshine", "princess", "football", "shadow", "654321", "111111", "000000",
	"access", "secret", "changeme",
}

var keyboardRows = []string{"qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"}

// assessPassword reports a heuristic result. Character classes are not evidence
// of strength. Inputs longer than strengthScanMax are unassessed, not truncated.
func assessPassword(secret []byte, pol resolvedPolicy) (string, []string) {
	if len(secret) > strengthScanMax {
		return StrengthUnassessed, []string{unknownStrength}
	}
	if predictable(secret, pol.Run) {
		return StrengthWeak, nil
	}
	n := len(secret)
	if utf8.Valid(secret) {
		n = utf8.RuneCount(secret)
	}
	if n < pol.Min {
		return StrengthWeak, nil
	}
	return StrengthAcceptable, nil
}

func predictable(secret []byte, run int) bool {
	if run < 3 {
		run = defaultPatternRun
	}
	if _, ok := commonExact[string(secret)]; ok {
		return true
	}
	if lower, ascii := asciiLower(secret); ascii {
		if _, ok := commonExact[string(lower)]; ok {
			return true
		}
		if containsCommon(string(lower)) {
			return true
		}
		if keyboard(lower, run) {
			return true
		}
	}
	return repeatedByte(secret, run) || sequential(secret, run) || blockRepeat(secret, run)
}

func containsCommon(lower string) bool {
	for w := range commonExact {
		if len(w) >= 8 && strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

func asciiLower(b []byte) ([]byte, bool) {
	out := make([]byte, len(b))
	for i, c := range b {
		if c > 127 {
			return nil, false
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out, true
}

func repeatedByte(b []byte, run int) bool {
	if run < 1 || len(b) < run {
		return false
	}
	n := 1
	for i := 1; i < len(b); i++ {
		if b[i] == b[i-1] {
			n++
			if n >= run {
				return true
			}
			continue
		}
		n = 1
	}
	return false
}

func sequential(b []byte, run int) bool {
	if len(b) < run {
		return false
	}
	up, down := 1, 1
	for i := 1; i < len(b); i++ {
		if b[i] == b[i-1]+1 {
			up++
		} else {
			up = 1
		}
		if b[i]+1 == b[i-1] {
			down++
		} else {
			down = 1
		}
		if up >= run || down >= run {
			return true
		}
	}
	return false
}

func keyboard(lower []byte, run int) bool {
	s := string(lower)
	for _, row := range keyboardRows {
		if containsRun(s, row, run) || containsRun(s, reverseASCII(row), run) {
			return true
		}
	}
	return false
}

func containsRun(s, row string, run int) bool {
	if len(row) < run {
		return false
	}
	for i := 0; i+run <= len(row); i++ {
		if strings.Contains(s, row[i:i+run]) {
			return true
		}
	}
	return false
}

func reverseASCII(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// blockRepeat is O(64*n). The scan ceiling is strengthScanMax.
func blockRepeat(b []byte, run int) bool {
	if len(b) < run*2 {
		return false
	}
	max := 64
	if len(b)/2 < max {
		max = len(b) / 2
	}
	for size := 1; size <= max; size++ {
		if len(b)%size != 0 {
			continue
		}
		same := true
		for i := size; i < len(b); i++ {
			if b[i] != b[i-size] {
				same = false
				break
			}
		}
		if same && size*2 >= run {
			return true
		}
	}
	return false
}
