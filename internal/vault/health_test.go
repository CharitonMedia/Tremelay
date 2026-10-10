package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPasswordStrengthIsNotCharacterClasses(t *testing.T) {
	pol := (healthPolicy{}).resolve()
	weak := [][]byte{
		[]byte("password"),
		[]byte("Password123!"),
		[]byte("qwertyuiop"),
		[]byte("abcdefghijkl"),
		[]byte("aaaaaaaaaaaa"),
		[]byte("aaaaaaaaaaaa!"),
		[]byte("!aaaaaaaaaaaa"),
		[]byte("abc!!!!!!defg"),
		[]byte("abcabcabcabc"),
	}
	if got, _ := assessPassword([]byte("k9#aaaaa$m2qz"), pol); got != StrengthAcceptable {
		t.Fatalf("short run %s", got)
	}
	shortRun := pol
	shortRun.Run = 4
	if got, _ := assessPassword([]byte("k9#aaaa$m2qz!"), shortRun); got != StrengthWeak {
		t.Fatalf("lowered run %s", got)
	}
	for _, secret := range weak {
		if got, _ := assessPassword(secret, pol); got != StrengthWeak {
			t.Fatalf("%q strength %s", secret, got)
		}
	}
	mixed := []byte("correct horse battery staple")
	if got, _ := assessPassword(mixed, pol); got != StrengthAcceptable {
		t.Fatalf("class-light passphrase %s", got)
	}
	unicode := []byte("правильно и длинно")
	if got, _ := assessPassword(unicode, pol); got != StrengthAcceptable {
		t.Fatalf("unicode %s", got)
	}
	malformed := append([]byte("ok-passphrase"), 0xff)
	if got, _ := assessPassword(malformed, pol); got != StrengthAcceptable {
		t.Fatalf("malformed %s", got)
	}
	long := randBytesT(t, strengthScanMax+32)
	if got, unknown := assessPassword(long, pol); got != StrengthUnassessed || len(unknown) != 1 || unknown[0] != unknownStrength {
		t.Fatalf("long %s %v", got, unknown)
	}

	_, _, session := mustCreate(t, nil)
	stored, err := session.Put("wide", "password", malformed, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := session.Get(stored.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Secret, malformed) {
		t.Fatal("malformed secret was normalized")
	}
	wide, err := session.Put("long", "password", long, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got, err = session.Get(wide.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Secret) != len(long) || !bytes.Equal(got.Secret, long) {
		t.Fatal("long secret was truncated")
	}
	health, err := session.Health(wide.ID)
	if err != nil {
		t.Fatal(err)
	}
	if health.Strength != StrengthUnassessed || health.Evidence == EvidenceComplete {
		t.Fatalf("long health %+v", health)
	}
}

func TestReuseTracksAffectedPasswordsOnly(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	shared := []byte("violet-anchor-91")
	if got, _ := assessPassword(shared, (healthPolicy{}).resolve()); got != StrengthAcceptable {
		t.Fatalf("fixture %s", got)
	}
	first, err := session.Put("one", "password", shared, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h, err := session.Health(first.ID)
	if err != nil || finding(h, ReasonReused) {
		t.Fatalf("self reuse %+v %v", h, err)
	}
	second, err := session.Put("two", "password", append([]byte(nil), shared...), PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if h, err = session.Health(first.ID); err != nil || !finding(h, ReasonReused) {
		t.Fatalf("peer %+v %v", h, err)
	}
	if h, err = session.Health(second.ID); err != nil || !finding(h, ReasonReused) {
		t.Fatalf("new %+v %v", h, err)
	}
	other, err := session.Put("api", "api_key", shared, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if h, err = session.Health(other.ID); err != nil || finding(h, ReasonReused) || h.Evidence == EvidenceComplete {
		t.Fatalf("api key treated as password %+v %v", h, err)
	}
	replaced, err := session.Replace(first.ID, strongPass(t), LifecycleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if replaced.ID != first.ID || replaced.Type != "password" || !replaced.Lifecycle.CreatedAt.Equal(first.Lifecycle.CreatedAt) {
		t.Fatal("replace retargeted the credential")
	}
	if h, err = session.Health(first.ID); err != nil || finding(h, ReasonReused) {
		t.Fatalf("replaced %+v %v", h, err)
	}
	if h, err = session.Health(second.ID); err != nil || finding(h, ReasonReused) {
		t.Fatalf("peer not cleared %+v %v", h, err)
	}
}

func TestReplaceRollbackKeepsSecretHealthAndPeers(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	shared := []byte("violet-anchor-91")
	first, err := session.Put("one", "password", shared, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := session.Put("two", "password", append([]byte(nil), shared...), PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	before := len(session.audit)
	head := session.header.AuditHead
	session.commitFault = func() error { return errors.New("full") }
	_, err = session.Replace(first.ID, strongPass(t), LifecycleOptions{})
	if !errors.Is(err, ErrAudit) {
		t.Fatal(err)
	}
	if len(session.audit) != before || session.header.AuditHead != head {
		t.Fatal("failed replace advanced the chain")
	}
	if !bytes.Equal(session.creds[credIndex(session.creds, first.ID)].Secret, shared) {
		t.Fatal("old secret was replaced")
	}
	h := session.present(session.creds[credIndex(session.creds, second.ID)])
	if !finding(h, ReasonReused) {
		t.Fatalf("peer health changed %+v", h)
	}
	session.commitFault = nil
	if !bytes.Equal(mustGet(t, session, first.ID), shared) {
		t.Fatal("secret missing after the fault cleared")
	}
}

func TestCompromiseBoundaryIsPrefixOnly(t *testing.T) {
	var logs bytes.Buffer
	_, _, session := mustCreate(t, log.New(&logs, "", 0))
	secret := strongPass(t)
	checker := &fakeChecker{hashes: map[string]struct{}{}}
	sum := sha256.Sum256(secret)
	checker.hashes[hex.EncodeToString(sum[:])] = struct{}{}
	if err := session.SetCompromiseChecker(checker); err != nil {
		t.Fatal(err)
	}
	stored, err := session.Put("pw", "password", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(checker.queries) != 0 {
		t.Fatal("lookup ran without opt-in")
	}
	h, err := session.Health(stored.ID)
	if err != nil || h.Compromise != CompromiseNotChecked || finding(h, ReasonCompromised) {
		t.Fatalf("default %+v %v", h, err)
	}
	policy := DefaultHealthPolicy()
	policy.CompromiseOptIn = true
	if err := session.SetHealthPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if len(checker.queries) != 1 || checker.queries[0].Algorithm != "sha256" || len(checker.queries[0].Prefix) != compromisePrefixHex {
		t.Fatalf("query %+v", checker.queries)
	}
	if strings.Contains(checker.queries[0].Prefix, string(secret)) {
		t.Fatal("query carried the password")
	}
	h, err = session.Health(stored.ID)
	if err != nil || h.Compromise != CompromiseMatch || !finding(h, ReasonCompromised) || h.Evidence != EvidenceComplete {
		t.Fatalf("match %+v %v", h, err)
	}
	if h.Fresh && len(h.Findings) > 0 && h.Evidence == EvidenceComplete {
		// A match is complete evidence and is still not a safety claim.
	}

	sentinel := "checker-failed-" + randHex(t, 16)
	checker.err = errors.New(sentinel)
	if err := session.RefreshHealth(stored.ID); err != nil {
		t.Fatal(err)
	}
	h, err = session.Health(stored.ID)
	if err != nil || h.Compromise != CompromiseMatch || !finding(h, ReasonCompromised) {
		t.Fatalf("failure downgraded %+v %v", h, err)
	}
	checker.err = nil
	checker.malformed = []string{"zz", "GGGG"}
	if err := session.RefreshHealth(stored.ID); err != nil {
		t.Fatal(err)
	}
	h, err = session.Health(stored.ID)
	if err != nil || h.Compromise != CompromiseMatch {
		t.Fatalf("malformed downgraded %+v %v", h, err)
	}
	checker.malformed = nil
	checker.hashes = map[string]struct{}{}
	clean := strongPass(t)
	other, err := session.Put("clean", "password", clean, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h, err = session.Health(other.ID)
	if err != nil || h.Compromise != CompromiseClear || finding(h, ReasonCompromised) || h.Evidence != EvidenceComplete {
		t.Fatalf("negative %+v %v", h, err)
	}
	weak, err := session.Put("common", "password", []byte("password123"), PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h, err = session.Health(weak.ID)
	if err != nil || h.Compromise != CompromiseClear || !finding(h, ReasonWeak) {
		t.Fatalf("clear is not safe %+v %v", h, err)
	}
	at := time.Now().UTC().Add(25 * time.Hour)
	session.clock = func() time.Time { return at }
	h, err = session.Health(other.ID)
	if err != nil || h.Compromise != CompromiseStale || h.Fresh || session.creds[credIndex(session.creds, other.ID)].Health.Compromise != CompromiseClear {
		t.Fatalf("stale clear %+v %v", h, err)
	}
	h, err = session.Health(stored.ID)
	if err != nil || h.Compromise != CompromiseMatch || !finding(h, ReasonCompromised) {
		t.Fatalf("stale match %+v %v", h, err)
	}
	assertNoHealthLeak(t, session, logs.Bytes(), secret, []byte(sentinel))
}

func TestDelayedCheckerCannotOverwriteReplacement(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	policy := DefaultHealthPolicy()
	policy.CompromiseOptIn = true
	if err := session.SetHealthPolicy(policy); err != nil {
		t.Fatal(err)
	}
	original := strongPass(t)
	stored, err := session.Put("pw", "password", original, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	replacement := strongPass(t)
	checker := &fakeChecker{hashes: map[string]struct{}{}}
	sum := sha256.Sum256(original)
	checker.hashes[hex.EncodeToString(sum[:])] = struct{}{}
	checker.hook = func() {
		checker.hook = nil
		if _, err := session.Replace(stored.ID, replacement, LifecycleOptions{}); err != nil {
			t.Errorf("inner replace %v", err)
		}
	}
	if err := session.SetCompromiseChecker(checker); err != nil {
		t.Fatal(err)
	}
	_, err = session.Replace(stored.ID, original, LifecycleOptions{})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("outer %v", err)
	}
	got := mustGet(t, session, stored.ID)
	if !bytes.Equal(got, replacement) {
		t.Fatal("delayed replace overwrote the committed secret")
	}
	h, err := session.Health(stored.ID)
	if err != nil || h.Compromise == CompromiseMatch || finding(h, ReasonCompromised) {
		t.Fatalf("delayed match applied %+v %v", h, err)
	}
}

func TestLifecycleBoundariesUseSessionClock(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := start
	session.clock = func() time.Time { return at }
	policy := DefaultHealthPolicy()
	policy.ReminderLead = 15 * time.Minute
	if err := session.SetHealthPolicy(policy); err != nil {
		t.Fatal(err)
	}
	every := time.Hour
	stored, err := session.Put("api", "api_key", strongPass(t), PutOptions{RotationEvery: every})
	if err != nil {
		t.Fatal(err)
	}
	h := mustHealth(t, session, stored.ID)
	if finding(h, ReasonRotationDue) || finding(h, ReasonRotationOverdue) {
		t.Fatalf("early %+v", h)
	}
	at = start.Add(time.Hour - 15*time.Minute)
	if err := session.RefreshHealth(stored.ID); err != nil {
		t.Fatal(err)
	}
	h = mustHealth(t, session, stored.ID)
	if !finding(h, ReasonRotationDue) || finding(h, ReasonRotationOverdue) {
		t.Fatalf("due window %+v", h)
	}
	notes := &MemoryNotifier{}
	if err := session.SetNotifier(notes); err != nil {
		t.Fatal(err)
	}
	if err := session.RefreshHealth(stored.ID); err != nil {
		t.Fatal(err)
	}
	if len(notes.Snapshot()) != 0 {
		t.Fatal("repeat refresh notified")
	}
	at = start.Add(time.Hour - time.Nanosecond)
	if err := session.RefreshHealth(stored.ID); err != nil {
		t.Fatal(err)
	}
	h = mustHealth(t, session, stored.ID)
	if !finding(h, ReasonRotationDue) || finding(h, ReasonRotationOverdue) {
		t.Fatalf("just before due %+v", h)
	}
	at = start.Add(time.Hour)
	if err := session.RefreshHealth(stored.ID); err != nil {
		t.Fatal(err)
	}
	h = mustHealth(t, session, stored.ID)
	if finding(h, ReasonRotationDue) || !finding(h, ReasonRotationOverdue) {
		t.Fatalf("overdue %+v", h)
	}
	if len(notes.Snapshot()) != 1 || notes.Snapshot()[0].Class != ClassHealth || notes.Snapshot()[0].AuditSeq == 0 || notes.Snapshot()[0].AuditHash == "" {
		t.Fatalf("reminder %+v", notes.Snapshot())
	}

	explicit := start.Add(2 * time.Hour)
	if _, err := session.SetLifecycle(stored.ID, LifecycleOptions{RotationDueAt: &explicit, RotationEvery: &every}); err != nil {
		t.Fatal(err)
	}
	at = start.Add(90 * time.Minute)
	if err := session.RefreshHealth(stored.ID); err != nil {
		t.Fatal(err)
	}
	h = mustHealth(t, session, stored.ID)
	if finding(h, ReasonRotationOverdue) || finding(h, ReasonRotationDue) {
		t.Fatalf("explicit date lost %+v", h)
	}
	replacedAt := start.Add(30 * time.Minute)
	at = replacedAt
	if _, err := session.Replace(stored.ID, strongPass(t), LifecycleOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := session.Get(stored.ID)
	if err != nil || got.Lifecycle.RotationDueAt == nil || !got.Lifecycle.RotationDueAt.Equal(explicit) {
		t.Fatal("replacement moved the explicit date")
	}
	zero := time.Duration(0)
	if _, err := session.SetLifecycle(stored.ID, LifecycleOptions{ClearRotation: true, RotationEvery: &zero}); err != nil {
		t.Fatal(err)
	}
	at = start.Add(48 * time.Hour)
	if err := session.RefreshHealth(stored.ID); err != nil {
		t.Fatal(err)
	}
	h = mustHealth(t, session, stored.ID)
	if finding(h, ReasonRotationDue) || finding(h, ReasonRotationOverdue) {
		t.Fatalf("disabled %+v", h)
	}

	exp := start.Add(time.Hour)
	review := start.Add(time.Hour)
	if _, err := session.SetLifecycle(stored.ID, LifecycleOptions{ExpiresAt: &exp, ReviewDueAt: &review}); err != nil {
		t.Fatal(err)
	}
	at = exp.Add(-time.Nanosecond)
	if err := session.RefreshHealth(stored.ID); err != nil {
		t.Fatal(err)
	}
	h = mustHealth(t, session, stored.ID)
	if finding(h, ReasonExpired) {
		t.Fatal("expired early")
	}
	at = review.Add(-15 * time.Minute)
	if err := session.RefreshHealth(stored.ID); err != nil {
		t.Fatal(err)
	}
	h = mustHealth(t, session, stored.ID)
	if !finding(h, ReasonReviewDue) || finding(h, ReasonExpired) {
		t.Fatalf("review %+v", h)
	}
	at = exp
	if err := session.RefreshHealth(stored.ID); err != nil {
		t.Fatal(err)
	}
	h = mustHealth(t, session, stored.ID)
	if !finding(h, ReasonExpired) || h.Evidence == EvidenceUnassessed {
		t.Fatalf("expired %+v", h)
	}
}

func TestIntervalResetsOnReplacementOnly(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	start := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	at := start
	session.clock = func() time.Time { return at }
	policy := DefaultHealthPolicy()
	policy.ReminderLead = 15 * time.Minute
	if err := session.SetHealthPolicy(policy); err != nil {
		t.Fatal(err)
	}
	stored, err := session.Put("api", "api_key", strongPass(t), PutOptions{RotationEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	at = start.Add(30 * time.Minute)
	if _, err := session.Replace(stored.ID, strongPass(t), LifecycleOptions{}); err != nil {
		t.Fatal(err)
	}
	at = start.Add(50 * time.Minute)
	if err := session.RefreshHealth(stored.ID); err != nil {
		t.Fatal(err)
	}
	h := mustHealth(t, session, stored.ID)
	if finding(h, ReasonRotationDue) || finding(h, ReasonRotationOverdue) {
		t.Fatalf("interval did not move %+v", h)
	}
	at = start.Add(30*time.Minute + time.Hour)
	if err := session.RefreshHealth(stored.ID); err != nil {
		t.Fatal(err)
	}
	h = mustHealth(t, session, stored.ID)
	if !finding(h, ReasonRotationOverdue) {
		t.Fatalf("new interval %+v", h)
	}
}

func TestHealthNotificationsDoNotContainOrRepeat(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	agent, err := session.CreateAgent("worker")
	if err != nil {
		t.Fatal(err)
	}
	if err := session.SetResponsePolicy(ResponsePolicy{High: ContainSuspendAgent}); err != nil {
		t.Fatal(err)
	}
	sink := &MemoryNotifier{}
	if err := session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	stored, err := session.Put("pw", "password", []byte("password"), PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if agentRecordState(session.agents, agent.ID) != agentStateActive {
		t.Fatal("health suspended the agent")
	}
	for _, ev := range session.audit {
		if ev.Action == actionContain {
			t.Fatal("health wrote containment")
		}
	}
	if len(sink.Snapshot()) != 1 || !strings.Contains(sink.Snapshot()[0].Reasons, ReasonWeak) {
		t.Fatalf("alert %+v", sink.Snapshot())
	}
	if err := session.RefreshHealth(stored.ID); err != nil {
		t.Fatal(err)
	}
	if len(sink.Snapshot()) != 1 {
		t.Fatal("refresh repeated the alert")
	}

	sink.Fail(errors.New("down"))
	policy := DefaultHealthPolicy()
	policy.MinPasswordLength = 20
	if err := session.SetHealthPolicy(policy); err != nil {
		t.Fatal(err)
	}
	// Sixteen acceptable characters become weak only because of the new minimum.
	strong, err := session.Put("long", "password", []byte("violet-anchor-91"), PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h := mustHealth(t, session, strong.ID)
	if !finding(h, ReasonWeak) {
		t.Fatalf("threshold %+v", h)
	}
	if err := session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	failed := 0
	for _, ev := range session.audit {
		if ev.Action == actionNotify && ev.Result == resultFailed && ev.Class == ClassHealth {
			failed++
		}
	}
	if failed == 0 {
		t.Fatal("delivery failure was not audited")
	}
	h = mustHealth(t, session, strong.ID)
	if !finding(h, ReasonWeak) {
		t.Fatal("delivery failure erased health")
	}
	sink.Fail(nil)
	if err := session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if err := session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	attempts := 0
	for _, ev := range session.audit {
		if ev.Action != actionHealth && ev.Action != actionRefresh {
			continue
		}
		if ev.CredID != strong.ID {
			continue
		}
		attempts += notifyAttempts(session.audit, ev.Seq)
	}
	if attempts > notifyAttemptLimit {
		t.Fatalf("attempts %d", attempts)
	}
	_ = failed
}

func TestHealthDeliveryFailureAndReopen(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	sink := &MemoryNotifier{}
	sink.Fail(errors.New("down"))
	if err := session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	stored, err := session.Put("pw", "password", []byte("password"), PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if notifyDelivered(session.audit, healthSeq(t, session, stored.ID)) {
		t.Fatal("failed sink was recorded as delivered")
	}
	source := healthSeq(t, session, stored.ID)
	if notifyAttempts(session.audit, source) != 1 || notifyDelivered(session.audit, source) {
		t.Fatal("reservation was not recorded")
	}
	h := mustHealth(t, session, stored.ID)
	if !finding(h, ReasonWeak) {
		t.Fatal("health missing after delivery failure")
	}
	sink.Fail(nil)
	session.Lock()
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(opened.Lock)
	if err := opened.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	if err := opened.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if len(sink.Snapshot()) != 2 || sink.Snapshot()[1].AuditSeq != source {
		t.Fatalf("reopen %+v", sink.Snapshot())
	}
	if err := opened.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if len(sink.Snapshot()) != 2 {
		t.Fatal("third delivery")
	}
	if notifyAttempts(opened.audit, source) != notifyAttemptLimit {
		t.Fatalf("attempts %d", notifyAttempts(opened.audit, source))
	}
}

func TestHealthWithoutSinkStaysDurable(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	stored, err := session.Put("pw", "password", []byte("password"), PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h := mustHealth(t, session, stored.ID)
	if !finding(h, ReasonWeak) {
		t.Fatal(h)
	}
	for _, ev := range session.audit {
		if ev.Action == actionNotify {
			t.Fatal("nil sink invented a delivery row")
		}
	}
	decided := false
	for _, ev := range session.audit {
		if ev.Action == actionRespond && ev.Result == resultDecisionNotify && ev.Class == ClassHealth {
			decided = true
		}
	}
	if !decided {
		t.Fatal("actionable health has no respond row")
	}
	sink := &MemoryNotifier{}
	if err := session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	if err := session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if len(sink.Snapshot()) != 1 {
		t.Fatalf("later sink %+v", sink.Snapshot())
	}
}

func TestLegacyAndInvalidHealth(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	now := time.Now().UTC()
	legacy := credential{
		ID:     strings.Repeat("ab", 16),
		Label:  "old",
		Type:   "api_key",
		Secret: []byte("legacy-secret-value"),
		Lifecycle: lifecycle{
			State:     StateActive,
			CreatedAt: now,
			UpdatedAt: now,
		},
	}
	reseal(t, session, []credential{legacy})
	session.Lock()
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatalf("legacy unlock %v", err)
	}
	t.Cleanup(opened.Lock)
	h, err := opened.Health(legacy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if h.Evidence != EvidenceUnassessed || h.Compromise != CompromiseNotChecked || len(h.Findings) != 0 {
		t.Fatalf("fabricated %+v", h)
	}
	got := mustGet(t, opened, legacy.ID)
	if !bytes.Equal(got, legacy.Secret) {
		t.Fatal("legacy secret unreadable")
	}
	opened.Lock()

	bad := legacy
	bad.Gen = 1
	bad.Health = &storedHealth{Gen: 1, At: now, Findings: []string{"pwned"}, Compromise: CompromiseNotChecked, Strength: StrengthUnsupported}
	path2, pass2, session2 := mustCreate(t, nil)
	reseal(t, session2, []credential{bad})
	session2.Lock()
	if _, err := Unlock(path2, pass2, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid health %v", err)
	}

	path3, pass3, session3 := mustCreate(t, nil)
	stored, err := session3.Put("pw", "password", []byte("password"), PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	next := cloneCreds(session3.creds)
	i := credIndex(next, stored.ID)
	next[i].Health.Findings = nil
	reseal(t, session3, next)
	session3.Lock()
	if _, err := Unlock(path3, pass3, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("disagreed health %v", err)
	}
	if _, err := VerifyAudit(path3, pass3); !errors.Is(err, ErrAudit) {
		t.Fatalf("verify %v", err)
	}
}

func TestHealthAuditTamperTruncationAndMigration(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	created := session.audit[0].Hash
	if _, err := session.Put("pw", "password", []byte("password"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	var healthRow auditEvent
	for _, ev := range session.audit {
		if ev.Action == actionHealth {
			healthRow = ev
		}
	}
	if healthRow.V != auditHealthVersion || healthRow.Reasons == "" {
		t.Fatalf("row %+v", healthRow)
	}
	tampered := append([]auditEvent{}, session.audit...)
	for i := range tampered {
		if tampered[i].Seq == healthRow.Seq {
			tampered[i].Reasons = ReasonExpired
		}
	}
	if err := verifyChain(tampered); !errors.Is(err, ErrAudit) {
		t.Fatalf("tampered reasons %v", err)
	}
	short := append([]auditEvent{}, session.audit[:healthRow.Seq-1]...)
	if len(short) == 0 || verifyChain(session.audit) != nil {
		t.Fatal("live chain")
	}
	db := mustOpen(t, path)
	if _, err := db.Exec(`UPDATE vault SET audit_head=?, audit_seq=? WHERE id=?`, created, 1, session.id); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAudit(path, pass); !errors.Is(err, ErrAudit) {
		t.Fatalf("truncated %v", err)
	}

	session.Lock()

	pathM, passM, fresh := mustCreate(t, nil)
	createdM := fresh.audit[0].Hash
	fresh.Lock()
	rewriteAudit(t, pathM, true)
	opened, err := Unlock(pathM, passM, nil)
	if err != nil {
		t.Fatalf("migrated unlock %v", err)
	}
	t.Cleanup(opened.Lock)
	var reasons string
	var gen int64
	var hash string
	if err := opened.db.QueryRow(`SELECT reasons, cred_gen, hash FROM audit WHERE seq=1`).Scan(&reasons, &gen, &hash); err != nil {
		t.Fatal(err)
	}
	if reasons != "" || gen != 0 || hash != createdM {
		t.Fatalf("migration reasons=%q gen=%d hash changed %v", reasons, gen, hash != createdM)
	}
	if _, err := opened.Put("more", "generic", strongPass(t), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := verifyChain(opened.audit); err != nil {
		t.Fatal(err)
	}
}

func TestReplaceKeepsGrantAndAgentCannotSeeHealth(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	secret := strongPass(t)
	stored, err := session.Put("api", "api_key", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := session.CreateAgent("worker")
	if err != nil {
		t.Fatal(err)
	}
	grant, err := session.IssueGrant(GrantSpec{
		AgentID:      agent.ID,
		CredentialID: stored.ID,
		Operations:   []string{OpHTTPRequest},
		Resource:     "svc:one",
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := session.Agent(agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := principal.Authorize(stored.ID, OpHTTPRequest, "svc:one"); err != nil {
		t.Fatal(err)
	}
	created := stored.Lifecycle.CreatedAt
	replaced, err := session.Replace(stored.ID, strongPass(t), LifecycleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if replaced.ID != stored.ID || replaced.Type != "api_key" || !replaced.Lifecycle.CreatedAt.Equal(created) || replaced.Lifecycle.State != StateActive {
		t.Fatalf("identity %+v", replaced)
	}
	got, err := principal.Authorize(stored.ID, OpHTTPRequest, "svc:one")
	if err != nil || got != grant.ID {
		t.Fatalf("grant %s %v", got, err)
	}
	methods := map[string]bool{}
	typ := reflect.TypeOf(principal)
	for i := 0; i < typ.NumMethod(); i++ {
		methods[typ.Method(i).Name] = true
	}
	for _, name := range []string{"Health", "ListHealth", "RefreshHealth", "Replace", "SetLifecycle", "SetHealthPolicy", "SetCompromiseChecker", "SetNotifier"} {
		if methods[name] {
			t.Fatalf("agent method %s", name)
		}
	}
	if _, ok := methods["Authorize"]; !ok || !methods["BrokerHTTP"] || !methods["Capabilities"] {
		t.Fatalf("methods %v", methods)
	}
}

func TestHealthSurfacesOmitSentinel(t *testing.T) {
	var logs bytes.Buffer
	_, _, session := mustCreate(t, log.New(&logs, "", 0))
	secret := []byte("sentinel-" + randHex(t, 24))
	checker := &fakeChecker{err: errors.New("boom-" + string(secret))}
	if err := session.SetCompromiseChecker(checker); err != nil {
		t.Fatal(err)
	}
	policy := DefaultHealthPolicy()
	policy.CompromiseOptIn = true
	if err := session.SetHealthPolicy(policy); err != nil {
		t.Fatal(err)
	}
	sink := &MemoryNotifier{}
	if err := session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	stored, err := session.Put("pw", "password", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Replace(stored.ID, nil, LifecycleOptions{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty replace %v", err)
	}
	if _, err := session.Health(string(secret)); !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrInvalid) {
		t.Fatalf("probe %v", err)
	}
	h := mustHealth(t, session, stored.ID)
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	notes, err := json.Marshal(sink.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var audit bytes.Buffer
	for _, ev := range session.audit {
		audit.WriteString(strings.Join([]string{ev.Action, ev.Result, ev.Reasons, ev.CredID, ev.CredType, ev.Class, ev.Operation}, "\n"))
		audit.WriteByte('\n')
	}
	assertNoHealthLeak(t, session, bytes.Join([][]byte{raw, notes, audit.Bytes(), logs.Bytes()}, []byte{'\n'}), secret, nil)
	for _, q := range checker.queries {
		if strings.Contains(q.Prefix, string(secret)) || q.Prefix == string(secret) {
			t.Fatal("prefix is the secret")
		}
	}
}

func TestAttemptWriteFailureDoesNotCallCheckerSink(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	sink := &MemoryNotifier{}
	if err := session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	n := 0
	session.commitFault = func() error {
		n++
		if n > 1 {
			return errors.New("attempt")
		}
		return nil
	}
	stored, err := session.Put("pw", "password", []byte("password"), PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sink.Snapshot()) != 0 {
		t.Fatal("sink ran without a reservation")
	}
	h := session.present(session.creds[credIndex(session.creds, stored.ID)])
	if !finding(h, ReasonWeak) {
		t.Fatal("health missing when delivery could not start")
	}
	session.commitFault = nil
	if err := session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if len(sink.Snapshot()) != 1 {
		t.Fatalf("recovered %+v", sink.Snapshot())
	}
}

func TestUnchangedReplacementKeepsKnownCompromise(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	policy := DefaultHealthPolicy()
	policy.CompromiseOptIn = true
	if err := session.SetHealthPolicy(policy); err != nil {
		t.Fatal(err)
	}
	secret := strongPass(t)
	checker := &fakeChecker{hashes: map[string]struct{}{}}
	sum := sha256.Sum256(secret)
	checker.hashes[hex.EncodeToString(sum[:])] = struct{}{}
	if err := session.SetCompromiseChecker(checker); err != nil {
		t.Fatal(err)
	}
	stored, err := session.Put("pw", "password", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h := mustHealth(t, session, stored.ID)
	if h.Compromise != CompromiseMatch || !finding(h, ReasonCompromised) {
		t.Fatalf("match %+v", h)
	}
	gen := h.SecretVersion
	updated := mustOne(t, session).Lifecycle.UpdatedAt
	checker.err = errors.New("down-" + randHex(t, 8))
	if _, err := session.Replace(stored.ID, append([]byte(nil), secret...), LifecycleOptions{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustGet(t, session, stored.ID), secret) {
		t.Fatal("identical replacement changed the secret")
	}
	if got := mustOne(t, session).Lifecycle.UpdatedAt; !got.Equal(updated) {
		t.Fatal("identical replacement moved UpdatedAt")
	}
	h = mustHealth(t, session, stored.ID)
	if h.SecretVersion != gen || h.Compromise != CompromiseMatch || !finding(h, ReasonCompromised) {
		t.Fatalf("match erased %+v", h)
	}
	other := strongPass(t)
	if _, err := session.Replace(stored.ID, other, LifecycleOptions{}); err != nil {
		t.Fatal(err)
	}
	h = mustHealth(t, session, stored.ID)
	if h.SecretVersion == gen || h.Compromise != CompromiseUnavailable || finding(h, ReasonCompromised) {
		t.Fatalf("changed value kept prior match %+v", h)
	}
	if !bytes.Equal(mustGet(t, session, stored.ID), other) {
		t.Fatal("changed replacement missing")
	}
}

func TestLegacyIdenticalReplacementKeepsAge(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	modified := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	now := modified.Add(48 * time.Hour)
	created := modified.Add(-24 * time.Hour)
	secret := strongPass(t)
	legacy := credential{
		ID:     strings.Repeat("cd", 16),
		Label:  "old",
		Type:   "password",
		Secret: append([]byte(nil), secret...),
		Lifecycle: lifecycle{
			State:     StateActive,
			CreatedAt: created,
			UpdatedAt: modified,
		},
	}
	reseal(t, session, []credential{legacy})
	session.Lock()
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatalf("legacy unlock %v", err)
	}
	t.Cleanup(opened.Lock)
	opened.clock = func() time.Time { return now }

	h := mustHealth(t, opened, legacy.ID)
	if h.Evidence != EvidenceUnassessed || h.SecretVersion != 0 || len(h.Findings) != 0 {
		t.Fatalf("reopen fabricated %+v", h)
	}
	meta := mustMeta(t, opened, legacy.ID)
	if !meta.UpdatedAt.Equal(modified) || !meta.CreatedAt.Equal(created) {
		t.Fatalf("reopen age %v created %v", meta.UpdatedAt, meta.CreatedAt)
	}

	every := time.Hour
	if _, err := opened.Replace(legacy.ID, append([]byte(nil), secret...), LifecycleOptions{RotationEvery: &every}); err != nil {
		t.Fatal(err)
	}
	h = mustHealth(t, opened, legacy.ID)
	if h.SecretVersion != 1 || !finding(h, ReasonRotationOverdue) || finding(h, ReasonRotationDue) {
		t.Fatalf("identical age %+v", h)
	}
	meta = mustMeta(t, opened, legacy.ID)
	if !meta.UpdatedAt.Equal(modified) || !meta.CreatedAt.Equal(created) || meta.RotationEvery != every {
		t.Fatalf("identical timestamps updated %v every %v", meta.UpdatedAt, meta.RotationEvery)
	}
	if !bytes.Equal(mustGet(t, opened, legacy.ID), secret) {
		t.Fatal("identical replacement changed the secret")
	}

	changed := strongPass(t)
	if bytes.Equal(changed, secret) {
		t.Fatal("fixture collision")
	}
	if _, err := opened.Replace(legacy.ID, changed, LifecycleOptions{}); err != nil {
		t.Fatal(err)
	}
	h = mustHealth(t, opened, legacy.ID)
	if h.SecretVersion != 2 || !finding(h, ReasonRotationDue) || finding(h, ReasonRotationOverdue) {
		t.Fatalf("changed replacement %+v", h)
	}
	meta = mustMeta(t, opened, legacy.ID)
	if !meta.UpdatedAt.Equal(now) || !meta.CreatedAt.Equal(created) {
		t.Fatalf("changed timestamps updated %v created %v", meta.UpdatedAt, meta.CreatedAt)
	}
	if !bytes.Equal(mustGet(t, opened, legacy.ID), changed) {
		t.Fatal("changed replacement missing")
	}
}

func TestCheckerConflictAuditsOuterAttempt(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	policy := DefaultHealthPolicy()
	policy.CompromiseOptIn = true
	if err := session.SetHealthPolicy(policy); err != nil {
		t.Fatal(err)
	}
	sentinel := "checker-callback-" + randHex(t, 12)
	checker := &fakeChecker{err: errors.New(sentinel)}
	if err := session.SetCompromiseChecker(checker); err != nil {
		t.Fatal(err)
	}
	secret := strongPass(t)
	stored, err := session.Put("pw", "password", secret, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	i := credIndex(session.creds, stored.ID)
	before := append([]byte(nil), session.creds[i].Secret...)
	expires := session.creds[i].Lifecycle.ExpiresAt
	min := session.hpolicy.MinPasswordLength

	hook := func() {
		if _, err := session.Health(stored.ID); err != nil {
			t.Errorf("inner health %v", err)
		}
	}
	run := func(action string, call func() error) {
		t.Helper()
		checker.hook = hook
		if err := call(); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s %v", action, err)
		}
		assertConflictDenial(t, session, action, sentinel)
	}
	run(actionRefresh, func() error { return session.RefreshHealth(stored.ID) })
	run(actionReplace, func() error {
		_, err := session.Replace(stored.ID, strongPass(t), LifecycleOptions{})
		return err
	})
	run(actionPut, func() error {
		_, err := session.Put("other", "password", strongPass(t), PutOptions{})
		return err
	})
	due := time.Now().UTC().Add(48 * time.Hour)
	run(actionLifecycle, func() error {
		_, err := session.SetLifecycle(stored.ID, LifecycleOptions{ExpiresAt: &due})
		return err
	})
	wider := policy
	wider.MinPasswordLength = 20
	run(actionHealthPolicy, func() error { return session.SetHealthPolicy(wider) })

	i = credIndex(session.creds, stored.ID)
	if i < 0 || !bytes.Equal(session.creds[i].Secret, before) || session.creds[i].Lifecycle.ExpiresAt != expires {
		t.Fatal("conflict committed credential state")
	}
	if len(session.creds) != 1 || session.hpolicy.MinPasswordLength != min {
		t.Fatal("conflict committed ingest or policy")
	}
}

func assertConflictDenial(t *testing.T, s *Session, action, sentinel string) {
	t.Helper()
	found := false
	for _, ev := range s.audit {
		if strings.Contains(ev.Reasons, sentinel) || strings.Contains(ev.Result, sentinel) || strings.Contains(ev.Action, sentinel) {
			t.Fatalf("callback text in %s", ev.Action)
		}
		if ev.Action == action && ev.Result == resultDenied && ev.Reasons == "" && ev.CredGen == 0 && ev.CredID == "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing denial for %s", action)
	}
}

func TestNoticeRowsRejectUnauthenticatedHealthColumns(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	sink := &MemoryNotifier{}
	if err := session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Put("pw", "password", []byte("password"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	var respondHash string
	seen := map[string]bool{}
	for _, ev := range session.audit {
		if !noticeAction(ev.Action) {
			continue
		}
		seen[ev.Action] = true
		if ev.Action == actionRespond {
			respondHash = ev.Hash
		}
		if ev.Reasons != "" || ev.CredGen != 0 {
			t.Fatalf("notice stored health columns %+v", ev)
		}
	}
	if !seen[actionRespond] || !seen[actionNotify] || respondHash == "" {
		t.Fatalf("notices %v", seen)
	}
	contain, err := nextAudit(session.audit, session.id, auditEvent{
		Action: actionContain,
		Result: resultFlagged,
		Class:  ClassHealth,
		RefSeq: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	session.audit = append(session.audit, contain)
	for _, action := range []string{actionRespond, actionNotify, actionContain} {
		idx := -1
		for i := range session.audit {
			if session.audit[i].Action == action {
				idx = i
			}
		}
		if idx < 0 {
			t.Fatalf("missing %s", action)
		}
		row, err := session.AuditBySeq(session.audit[idx].Seq, session.audit[idx].Hash)
		if err != nil || row.Reasons != "" || row.CredGen != 0 {
			t.Fatalf("%s read %+v %v", action, row, err)
		}
		session.audit[idx].Reasons = "forged-reason"
		session.audit[idx].CredGen = 999
		forged, err := session.AuditBySeq(session.audit[idx].Seq, "")
		if !errors.Is(err, ErrAudit) || forged.Reasons == "forged-reason" || forged.CredGen == 999 {
			t.Fatalf("%s forged read %+v %v", action, forged, err)
		}
		session.audit[idx].Reasons = ""
		session.audit[idx].CredGen = 0
	}
	session.Lock()

	db := mustOpen(t, path)
	for _, action := range []string{actionRespond, actionNotify} {
		res, err := db.Exec(`UPDATE audit SET reasons=?, cred_gen=? WHERE action=?`, "forged-reason", 999, action)
		if err != nil {
			t.Fatal(err)
		}
		n, err := res.RowsAffected()
		if err != nil || n == 0 {
			t.Fatalf("%s rows %d %v", action, n, err)
		}
	}
	var hash string
	if err := db.QueryRow(`SELECT hash FROM audit WHERE action=?`, actionRespond).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash != respondHash {
		t.Fatal("tamper rewrote the version-3 hash")
	}
	if _, err := VerifyAudit(path, pass); !errors.Is(err, ErrAudit) {
		t.Fatalf("verify %v", err)
	}
	if _, err := Unlock(path, pass, nil); !errors.Is(err, ErrAudit) {
		t.Fatalf("unlock %v", err)
	}
}

type fakeChecker struct {
	hashes    map[string]struct{}
	err       error
	malformed []string
	queries   []CompromiseQuery
	hook      func()
}

func (f *fakeChecker) Lookup(q CompromiseQuery) ([]string, error) {
	f.queries = append(f.queries, q)
	if f.hook != nil {
		hook := f.hook
		f.hook = nil
		hook()
	}
	if f.err != nil {
		return nil, f.err
	}
	if f.malformed != nil {
		return f.malformed, nil
	}
	var out []string
	for h := range f.hashes {
		if strings.HasPrefix(h, q.Prefix) && len(h) == sha256.Size*2 {
			out = append(out, h[len(q.Prefix):])
		}
	}
	return out, nil
}

func strongPass(t *testing.T) []byte {
	t.Helper()
	for i := 0; i < 8; i++ {
		b := []byte(hex.EncodeToString(randBytesT(t, 24)))
		if got, _ := assessPassword(b, (healthPolicy{}).resolve()); got == StrengthAcceptable {
			return b
		}
	}
	t.Fatal("no acceptable fixture")
	return nil
}

func healthSeq(t *testing.T, s *Session, id string) uint64 {
	t.Helper()
	var seq uint64
	for _, ev := range s.audit {
		if ev.Action == actionHealth && ev.CredID == id {
			seq = ev.Seq
		}
	}
	if seq == 0 {
		t.Fatal("missing health row")
	}
	return seq
}

func finding(h Health, code string) bool {
	for _, f := range h.Findings {
		if f == code {
			return true
		}
	}
	return false
}

func mustHealth(t *testing.T, s *Session, id string) Health {
	t.Helper()
	h, err := s.Health(id)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func mustGet(t *testing.T, s *Session, id string) []byte {
	t.Helper()
	got, err := s.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	return got.Secret
}

func mustMeta(t *testing.T, s *Session, id string) Lifecycle {
	t.Helper()
	got, err := s.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	return got.Lifecycle
}

func reseal(t *testing.T, s *Session, creds []credential) {
	t.Helper()
	plain, err := json.Marshal(document{
		Credentials:  creds,
		Agents:       s.agents,
		Grants:       s.grants,
		Detection:    s.detection,
		HealthPolicy: s.hpolicy,
		Organization: s.org,
		Memberships:  s.members,
		Requests:     s.requests,
	})
	if err != nil {
		t.Fatal(err)
	}
	nonce, ct, err := seal(s.dek, plain, dataAAD(s.id, s.header.AuditHead, s.header.AuditSeq))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE vault SET data_nonce=?, encrypted_document=? WHERE id=?`, nonce, ct, s.id); err != nil {
		t.Fatal(err)
	}
}

func assertNoHealthLeak(t *testing.T, s *Session, blob []byte, secret, extra []byte) {
	t.Helper()
	if bytes.Contains(blob, secret) {
		t.Fatal("secret reached a health surface")
	}
	if len(extra) > 0 && bytes.Contains(blob, extra) {
		t.Fatal("checker error reached a health surface")
	}
	for _, ev := range s.audit {
		if strings.Contains(ev.Reasons, string(secret)) || strings.Contains(ev.Result, string(secret)) {
			t.Fatal("audit row contains the secret")
		}
	}
}
