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
	noticeIndexVisits = 0
	if err := session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if noticeIndexVisits != before {
		t.Fatalf("notice visits %d want one pass of %d", noticeIndexVisits, before)
	}
	got := sink.Snapshot()
	if len(got) != 1 || got[0].Result != resultDeniedOrigin {
		t.Fatalf("delivered %+v", got)
	}
	noticeIndexVisits = 0
	if err := session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if len(sink.Snapshot()) != 1 {
		t.Fatal("second pass sent another alert")
	}
}
