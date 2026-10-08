package vault

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestCommitUpdatesDetectionIndexIncrementally(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	t.Cleanup(session.Lock)
	id := strings.Repeat("ab", 16)
	for i := 0; i < 64; i++ {
		if err := session.writeAudit(brokerRow(id, resultAllowed), session.creds, session.agents, session.grants); err != nil {
			t.Fatal(err)
		}
	}
	before := len(session.audit)
	detectionApplyVisits = 0
	if err := session.writeAudit(brokerRow(id, resultDeniedMissing), session.creds, session.agents, session.grants); err != nil {
		t.Fatal(err)
	}
	if got, want := detectionApplyVisits, len(session.audit)-before; got != want {
		t.Fatalf("commit visited %d rows, wrote %d", got, want)
	}
	if !reflect.DeepEqual(session.detection, detectionFromAudit(session.audit)) {
		t.Fatalf("mirror %+v", session.detection.Denials)
	}
	if !reflect.DeepEqual(session.denials.state(), session.detection) {
		t.Fatal("index diverged from the mirror")
	}
}

func TestFailedCommitRollsBackDetectionIndex(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	t.Cleanup(session.Lock)
	id := strings.Repeat("cd", 16)
	partial := auditEvent{Action: actionBroker, Result: resultDeniedMissing, AgentID: id, Operation: OpHTTPRequest}
	if err := session.writeAudit(partial, session.creds, session.agents, session.grants); err != nil {
		t.Fatal(err)
	}
	beforeDet := session.detection
	beforeAudit := append([]auditEvent(nil), session.audit...)
	beforeIdx := session.denials.state()
	session.commitFault = func() error { return errors.New("full") }
	if err := session.writeAudit(partial, session.creds, session.agents, session.grants); err == nil {
		t.Fatal("faulted commit succeeded")
	}
	session.commitFault = nil
	if len(session.audit) != len(beforeAudit) || !reflect.DeepEqual(session.detection, beforeDet) {
		t.Fatal("failed commit published audit or mirror")
	}
	if !reflect.DeepEqual(session.denials.state(), beforeIdx) {
		t.Fatal("failed commit published the index")
	}
	if err := session.writeAudit(partial, session.creds, session.agents, session.grants); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(session.detection, detectionFromAudit(session.audit)) {
		t.Fatalf("recovered mirror %+v", session.detection.Denials)
	}
	if session.detection.Denials[0].N != 2 {
		t.Fatalf("count %+v", session.detection.Denials)
	}
}

func TestReopenRebuildsDetectionIndexOnce(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	id := strings.Repeat("ef", 16)
	for i := 0; i < 40; i++ {
		result := resultAllowed
		if i%5 == 0 {
			result = resultDeniedMissing
		}
		if err := session.writeAudit(brokerRow(id, result), session.creds, session.agents, session.grants); err != nil {
			t.Fatal(err)
		}
	}
	want := session.detection
	session.Lock()
	detectionApplyVisits = 0
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(opened.Lock)
	if detectionApplyVisits != len(opened.audit) {
		t.Fatalf("rebuild visited %d rows for %d audit rows", detectionApplyVisits, len(opened.audit))
	}
	if !reflect.DeepEqual(opened.detection, want) {
		t.Fatalf("reopen mirror %+v want %+v", opened.detection.Denials, want.Denials)
	}
	if !reflect.DeepEqual(opened.denials.state(), detectionFromAudit(opened.audit)) {
		t.Fatal("rebuilt index does not match the chain")
	}
	detectionApplyVisits = 0
	if _, err := VerifyAudit(path, pass); err != nil {
		t.Fatal(err)
	}
	// The mirror is already stored, so verify builds the index once.
	if detectionApplyVisits != len(opened.audit) {
		t.Fatalf("verify visited %d rows for %d durable rows", detectionApplyVisits, len(opened.audit))
	}
}

func brokerRow(agentID, result string) auditEvent {
	return auditEvent{
		Action:    actionBroker,
		Result:    result,
		AgentID:   agentID,
		GrantID:   strings.Repeat("12", 16),
		CredID:    strings.Repeat("34", 16),
		CredType:  "api_key",
		Operation: OpHTTPRequest,
	}
}

func TestCommitAppendsAuditSuffix(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	t.Cleanup(session.Lock)
	for cap(session.audit)-len(session.audit) < 1 {
		if err := session.persistEvent(actionList, "", "", resultAllowed); err != nil {
			t.Fatal(err)
		}
		if len(session.audit) > 64 {
			t.Fatal("audit slice did not keep spare capacity")
		}
	}
	prefix := &session.audit[0]
	before := len(session.audit)
	session.commitFault = func() error { return errors.New("full") }
	if err := session.persistEvent(actionList, "", "", resultAllowed); err == nil {
		t.Fatal("faulted commit succeeded")
	}
	session.commitFault = nil
	if len(session.audit) != before || &session.audit[0] != prefix {
		t.Fatal("failed commit rebuilt the audit prefix")
	}
	if err := session.persistEvent(actionList, "", "", resultAllowed); err != nil {
		t.Fatal(err)
	}
	if len(session.audit) != before+1 || &session.audit[0] != prefix {
		t.Fatal("commit rebuilt the audit prefix")
	}
}

func TestAlertCommitAppendsAuditSuffix(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	t.Cleanup(session.Lock)
	for cap(session.audit)-len(session.audit) < 2 {
		if err := session.persistEvent(actionGet, "", "", resultAllowed); err != nil {
			t.Fatal(err)
		}
		if len(session.audit) > 80 {
			t.Fatal("audit slice did not keep spare capacity")
		}
	}
	prefix := &session.audit[0]
	before := len(session.audit)
	if err := session.writeAudit(auditEvent{
		Action: actionBroker, Result: resultDeniedSSRF,
	}, session.creds, session.agents, session.grants); err != nil {
		t.Fatal(err)
	}
	if &session.audit[0] != prefix {
		t.Fatal("alert commit rebuilt the audit prefix")
	}
	if len(session.audit) != before+2 {
		t.Fatalf("alert appended %d rows", len(session.audit)-before)
	}
}

func TestAuditHistoryDoesNotRescanDenials(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	t.Cleanup(session.Lock)
	noise := strings.Repeat("ab", 16)
	for i := 0; i < 40; i++ {
		if err := session.writeAudit(brokerRow(noise, resultDeniedMissing), session.creds, session.agents, session.grants); err != nil {
			t.Fatal(err)
		}
	}
	agent, err := session.CreateAgent("target")
	if err != nil {
		t.Fatal(err)
	}
	target := agent.ID
	if err := session.SetResponsePolicy(ResponsePolicy{High: ContainSuspendAgent}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := session.writeAudit(brokerRow(target, resultDeniedMissing), session.creds, session.agents, session.grants); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if err := session.writeAudit(brokerRow(target, resultDeniedAgent), session.creds, session.agents, session.grants); err != nil {
			t.Fatal(err)
		}
	}
	auditPrefixScans = 0
	var got []AuditRecord
	after := uint64(0)
	for {
		page, err := session.AuditHistory(AuditFilter{AfterSeq: after, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		got = append(got, page...)
		after = page[len(page)-1].Seq
	}
	if auditPrefixScans != 0 {
		t.Fatalf("history walked %d prefix rows", auditPrefixScans)
	}
	if len(got) != len(session.audit) {
		t.Fatalf("history returned %d rows, chain has %d", len(got), len(session.audit))
	}
	for i, rec := range got {
		ev := session.audit[i]
		want := classifyState(session.audit, ev, session.agents, session.grants)
		if rec.Seq != ev.Seq || rec.Class != want.Class || rec.Severity != want.Severity {
			t.Fatalf("seq %d got %s/%s want %s/%s", ev.Seq, rec.Class, rec.Severity, want.Class, want.Severity)
		}
	}
	auditPrefixScans = 0
	miss, err := session.AuditHistory(AuditFilter{AgentID: strings.Repeat("ff", 16), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(miss) != 0 || auditPrefixScans != 0 {
		t.Fatalf("nonmatching filter returned %d and walked %d", len(miss), auditPrefixScans)
	}
	page, err := session.AuditHistory(AuditFilter{AgentID: target, Action: actionBroker, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 6 || page[2].Class != ClassRepeatedDenial || page[2].Result != resultDeniedMissing || page[3].Class != ClassExpectedDenial || page[3].Result != resultDeniedAgent {
		t.Fatalf("target page %+v", page)
	}
}

func TestIncomingClassMatchesChain(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	t.Cleanup(session.Lock)
	id := strings.Repeat("a1", 16)
	check := func(want Classification) {
		t.Helper()
		ev, err := nextAudit(session.audit, session.id, brokerRow(id, resultDeniedMissing))
		if err != nil {
			t.Fatal(err)
		}
		got := session.classifyIncoming(ev, session.agents, session.grants)
		chain := append(append([]auditEvent{}, session.audit...), ev)
		full := classifyState(chain, ev, session.agents, session.grants)
		if got != full || got != want {
			t.Fatalf("incoming %+v chain %+v want %+v", got, full, want)
		}
		if err := session.writeAudit(brokerRow(id, resultDeniedMissing), session.creds, session.agents, session.grants); err != nil {
			t.Fatal(err)
		}
	}
	ordinary := Classification{Class: ClassExpectedDenial, Severity: SeverityLow}
	check(ordinary)
	check(ordinary)
	check(Classification{Class: ClassRepeatedDenial, Severity: SeverityHigh})
}

func TestNoticeIndexMatchesScans(t *testing.T) {
	events := []auditEvent{
		{Seq: 1, Action: actionBroker, Result: resultDeniedSSRF},
		{Seq: 2, Action: actionRespond, Result: resultDecisionNotify, RefSeq: 1},
		{Seq: 3, Action: actionBroker, Result: resultDeniedOrigin},
		{Seq: 4, Action: actionRespond, Result: resultDecisionFlag, RefSeq: 3},
		{Seq: 5, Action: actionBroker, Result: resultDeniedSSRF},
		{Seq: 6, Action: actionNotify, Result: resultFailed, RefSeq: 5},
		{Seq: 7, Action: actionBroker, Result: resultDeniedSSRF},
		{Seq: 8, Action: actionRespond, Result: resultDecisionNotify, RefSeq: 7},
		{Seq: 9, Action: actionNotify, Result: resultAttempted, RefSeq: 7},
		{Seq: 10, Action: actionNotify, Result: resultFailed, RefSeq: 7},
		{Seq: 11, Action: actionNotify, Result: resultAttempted, RefSeq: 7},
		{Seq: 12, Action: actionBroker, Result: resultAllowed},
	}
	idx := noticeIndex(events)
	for _, ev := range events {
		if noticeAction(ev.Action) {
			continue
		}
		st := idx[ev.Seq]
		if st.chosen() != notifyChosen(events, ev.Seq) {
			t.Fatalf("seq %d chosen index %v scan %v", ev.Seq, st.chosen(), notifyChosen(events, ev.Seq))
		}
		if st.attempts != notifyAttempts(events, ev.Seq) || st.delivered != notifyDelivered(events, ev.Seq) {
			t.Fatalf("seq %d attempts %d delivered %v", ev.Seq, st.attempts, st.delivered)
		}
	}
	if idx[3].chosen() || !idx[5].chosen() || idx[5].attempts != 1 || idx[7].attempts != 2 {
		t.Fatalf("flag/legacy/modern %+v %+v %+v", idx[3], idx[5], idx[7])
	}
}

func TestDeliverPendingIndexesRoutineHistoryOnce(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	t.Cleanup(session.Lock)
	for i := 0; i < 64; i++ {
		if err := session.persistEvent(actionList, "", "", resultAllowed); err != nil {
			t.Fatal(err)
		}
	}
	if err := session.SetResponsePolicy(ResponsePolicy{High: ContainFlag}); err != nil {
		t.Fatal(err)
	}
	if err := session.writeAudit(auditEvent{
		Action: actionBroker, Result: resultDeniedSSRF,
	}, session.creds, session.agents, session.grants); err != nil {
		t.Fatal(err)
	}
	if err := session.SetResponsePolicy(ResponsePolicy{}); err != nil {
		t.Fatal(err)
	}
	if err := session.writeAudit(auditEvent{
		Action: actionBroker, Result: resultDeniedOrigin,
	}, session.creds, session.agents, session.grants); err != nil {
		t.Fatal(err)
	}
	sink := &MemoryNotifier{}
	if err := session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	before := len(session.audit)
	noticeScanVisits = 0
	noticeApplyVisits = 0
	if err := session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if noticeScanVisits != 0 {
		t.Fatalf("pending delivery scanned %d rows", noticeScanVisits)
	}
	wrote := len(session.audit) - before
	if noticeApplyVisits != wrote {
		t.Fatalf("pending delivery applied %d rows, wrote %d", noticeApplyVisits, wrote)
	}
	got := sink.Snapshot()
	if len(got) != 1 || got[0].Result != resultDeniedOrigin {
		t.Fatalf("delivered %+v", got)
	}
	noticeScanVisits = 0
	noticeApplyVisits = 0
	if err := session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if noticeScanVisits != 0 || noticeApplyVisits != 0 {
		t.Fatalf("second pass scanned %d applied %d", noticeScanVisits, noticeApplyVisits)
	}
	if len(sink.Snapshot()) != 1 {
		t.Fatal("second pass sent another alert")
	}
}

func TestSustainedHighRiskSkipsNoticeScan(t *testing.T) {
	_, _, session := mustCreate(t, nil)
	t.Cleanup(session.Lock)
	writeSSRF := func() {
		t.Helper()
		if err := session.writeAudit(auditEvent{
			Action: actionBroker, Result: resultDeniedSSRF,
		}, session.creds, session.agents, session.grants); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 40; i++ {
		writeSSRF()
	}
	check := func() int {
		t.Helper()
		noticeScanVisits = 0
		noticeApplyVisits = 0
		before := len(session.audit)
		writeSSRF()
		wrote := len(session.audit) - before
		if noticeScanVisits != 0 {
			t.Fatalf("scanned %d rows after %d history", noticeScanVisits, before)
		}
		if noticeApplyVisits != wrote || wrote > 4 {
			t.Fatalf("applied %d rows, wrote %d", noticeApplyVisits, wrote)
		}
		return wrote
	}
	if wrote := check(); wrote != 2 {
		t.Fatalf("nil sink wrote %d rows", wrote)
	}
	sink := &MemoryNotifier{}
	if err := session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	if wrote := check(); wrote != 4 {
		t.Fatalf("notifier wrote %d rows", wrote)
	}
	if len(sink.Snapshot()) != 1 || sink.Snapshot()[0].Class != ClassSSRF {
		t.Fatalf("delivered %+v", sink.Snapshot())
	}
}

func TestNoticeIndexRollbackAndReopen(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	if err := session.SetResponsePolicy(ResponsePolicy{High: ContainFlag}); err != nil {
		t.Fatal(err)
	}
	if err := session.writeAudit(auditEvent{
		Action: actionBroker, Result: resultDeniedSSRF,
	}, session.creds, session.agents, session.grants); err != nil {
		t.Fatal(err)
	}
	if err := session.SetResponsePolicy(ResponsePolicy{}); err != nil {
		t.Fatal(err)
	}
	if err := session.writeAudit(auditEvent{
		Action: actionBroker, Result: resultDeniedOrigin,
	}, session.creds, session.agents, session.grants); err != nil {
		t.Fatal(err)
	}
	before := cloneNotices(session.notices)
	beforeN := len(session.audit)
	session.commitFault = func() error { return errors.New("full") }
	if err := session.writeAudit(auditEvent{
		Action: actionBroker, Result: resultDeniedRedirect,
	}, session.creds, session.agents, session.grants); err == nil {
		t.Fatal("faulted commit succeeded")
	}
	session.commitFault = nil
	if len(session.audit) != beforeN || !reflect.DeepEqual(session.notices, before) {
		t.Fatal("failed commit published notice state")
	}
	if err := session.writeAudit(auditEvent{
		Action: actionBroker, Result: resultDeniedRedirect,
	}, session.creds, session.agents, session.grants); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(session.notices, noticeIndex(session.audit)) {
		t.Fatal("index diverged from the chain")
	}
	session.Lock()
	noticeApplyVisits = 0
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(opened.Lock)
	if noticeApplyVisits != len(opened.audit) {
		t.Fatalf("rebuild visited %d rows for %d audit rows", noticeApplyVisits, len(opened.audit))
	}
	if !reflect.DeepEqual(opened.notices, noticeIndex(opened.audit)) {
		t.Fatal("reopen index does not match the chain")
	}
	sink := &MemoryNotifier{}
	if err := opened.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	noticeScanVisits = 0
	if err := opened.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if noticeScanVisits != 0 {
		t.Fatalf("reopen delivery scanned %d rows", noticeScanVisits)
	}
	var origin, redirect, ssrf int
	for _, n := range sink.Snapshot() {
		switch n.Result {
		case resultDeniedOrigin:
			origin++
		case resultDeniedRedirect:
			redirect++
		case resultDeniedSSRF:
			ssrf++
		default:
			t.Fatalf("unexpected alert %+v", n)
		}
	}
	if origin != 1 || redirect != 1 || ssrf != 0 {
		t.Fatalf("origin %d redirect %d ssrf %d", origin, redirect, ssrf)
	}
}

func cloneNotices(in map[uint64]noticeSrc) map[uint64]noticeSrc {
	out := make(map[uint64]noticeSrc, len(in))
	for seq, st := range in {
		out[seq] = st
	}
	return out
}
