package vault

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestM5ClassifyTable(t *testing.T) {
	agent := strings.Repeat("ab", 16)
	cases := []struct {
		ev   auditEvent
		want Classification
	}{
		{auditEvent{Action: actionPut, Result: resultAllowed}, Classification{ClassRoutine, SeverityInfo}},
		{auditEvent{Action: actionGet, Result: resultDenied}, Classification{ClassExpectedDenial, SeverityLow}},
		{auditEvent{Action: actionUnlock, Result: resultDenied}, Classification{ClassExpectedDenial, SeverityLow}},
		{auditEvent{Action: actionAuthorize, Result: resultDeniedSecret, AgentID: agent}, Classification{ClassSecretProbe, SeverityHigh}},
		{auditEvent{Action: actionBroker, Result: resultDeniedOrigin, AgentID: agent}, Classification{ClassOriginMismatch, SeverityHigh}},
		{auditEvent{Action: actionBroker, Result: resultDeniedSSRF, AgentID: agent}, Classification{ClassSSRF, SeverityCritical}},
		{auditEvent{Action: actionBroker, Result: resultDeniedRedirect, AgentID: agent}, Classification{ClassRedirectEscape, SeverityCritical}},
		{auditEvent{Action: actionBroker, Result: resultDeniedMethod, AgentID: agent}, Classification{ClassPolicyViolation, SeverityHigh}},
		{auditEvent{Action: actionBroker, Result: resultDeniedPath, AgentID: agent}, Classification{ClassPolicyViolation, SeverityHigh}},
		{auditEvent{Action: actionBroker, Result: resultDeniedAction, AgentID: agent}, Classification{ClassPolicyViolation, SeverityHigh}},
		{auditEvent{Action: actionBroker, Result: resultDeniedRevoked, AgentID: agent}, Classification{ClassReplay, SeverityHigh}},
		{auditEvent{Action: actionGrantRevoke, Result: resultDenied}, Classification{ClassExpectedDenial, SeverityLow}},
		{auditEvent{Action: actionBroker, Result: resultDeniedAbuse, AgentID: agent}, Classification{ClassRate, SeverityHigh}},
		{auditEvent{Action: actionBroker, Result: resultDeniedDestructive, AgentID: agent}, Classification{ClassDestructive, SeverityHigh}},
		{auditEvent{Action: actionBroker, Result: resultDeniedDestination, AgentID: agent}, Classification{ClassExpectedDenial, SeverityLow}},
		{auditEvent{Action: actionNotify, Result: resultFailed, Class: ClassSSRF}, Classification{ClassNotice, SeverityInfo}},
		{auditEvent{Action: actionNotify, Result: resultAttempted, Class: ClassSSRF}, Classification{ClassNotice, SeverityInfo}},
		{auditEvent{Action: actionContain, Result: resultSuspended, Class: ClassSSRF}, Classification{ClassNotice, SeverityInfo}},
		{auditEvent{Action: actionRespond, Result: resultDecisionNotify, Class: ClassSSRF}, Classification{ClassNotice, SeverityInfo}},
		{auditEvent{Action: actionRespond, Result: resultDecisionFlag, Class: ClassSSRF}, Classification{ClassNotice, SeverityInfo}},
		{auditEvent{Result: "caller-supplied"}, Classification{ClassAuditTamper, SeverityCritical}},
	}
	for _, tc := range cases {
		got := classify(nil, tc.ev)
		if got != tc.want {
			t.Fatalf("%s/%s: got %+v want %+v", tc.ev.Action, tc.ev.Result, got, tc.want)
		}
	}
	var rows []auditEvent
	for i := 0; i < detectionThreshold-1; i++ {
		rows = append(rows, auditEvent{Seq: uint64(i + 1), Action: actionBroker, Result: resultDeniedMissing, AgentID: agent})
	}
	if classify(rows, rows[len(rows)-1]).Class != ClassExpectedDenial {
		t.Fatal("threshold crossed early")
	}
	rows = append(rows, auditEvent{Seq: uint64(len(rows) + 1), Action: actionBroker, Result: resultDeniedMissing, AgentID: agent})
	if got := classify(rows, rows[len(rows)-1]); got.Class != ClassRepeatedDenial || got.Severity != SeverityHigh {
		t.Fatalf("repeated %+v", got)
	}
	// A later allow must not rewrite the earlier row's class.
	if classify(rows, rows[0]).Class != ClassExpectedDenial {
		t.Fatal("history was reclassified")
	}
	// Grant suspension uses resultSuspended and must not hide an active agent's denials.
	held := []auditEvent{{Seq: 1, Action: actionContain, Result: resultSuspended, AgentID: agent, Class: ClassPolicyViolation, RefSeq: 1}}
	for i := 0; i < detectionThreshold; i++ {
		held = append(held, auditEvent{Seq: uint64(len(held) + 1), Action: actionBroker, Result: resultDeniedAgent, AgentID: agent})
	}
	if classify(held, held[len(held)-1]).Class != ClassRepeatedDenial {
		t.Fatal("grant suspension suppressed an active denial")
	}
	// Agent suspension stays low after the triggering row leaves the lookback.
	suspended := []auditEvent{
		{Seq: 1, Action: actionBroker, Result: resultDeniedSSRF, AgentID: agent},
		{Seq: 2, Action: actionContain, Result: resultAgentSuspended, AgentID: agent, Class: ClassSSRF, RefSeq: 1},
	}
	for i := 0; i < detectionLookback; i++ {
		suspended = append(suspended, auditEvent{Seq: uint64(len(suspended) + 1), Action: actionBroker, Result: resultDeniedAgent, AgentID: agent})
	}
	if got := classify(suspended, suspended[len(suspended)-1]); got.Class != ClassExpectedDenial || got.Severity != SeverityLow {
		t.Fatalf("suspended denial %+v", got)
	}
	if classify(suspended, suspended[0]).Severity != SeverityCritical {
		t.Fatal("trigger was downgraded")
	}
	if err := validateDetection(detectionState{Denials: []denialSubject{{AgentID: "not-an-id", N: 1}}}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("bad id %v", err)
	}
	if err := validateDetection(detectionState{Denials: []denialSubject{{AgentID: agent, N: -1}}}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("negative %v", err)
	}
	if err := validateDetection(detectionState{Denials: []denialSubject{{AgentID: agent, N: detectionLookback + 1}}}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("over lookback %v", err)
	}
	secret := []byte("detection-secret-sentinel-value")
	if err := validateDetection(detectionState{Denials: []denialSubject{{AgentID: string(secret), N: 1}}}); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	mismatched := []auditEvent{{Seq: 1, Action: actionBroker, Result: resultDeniedMissing, AgentID: agent}}
	if err := checkDetection(mismatched, detectionState{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("suppressed counter %v", err)
	}
}

func TestM5ChainIntegrity(t *testing.T) {
	id := strings.Repeat("ab", 16)
	agent := strings.Repeat("cd", 16)
	grant := strings.Repeat("ef", 16)
	cred := strings.Repeat("12", 16)
	create, err := nextEvent(nil, actionCreate, id, "", "", resultAllowed)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := nextAudit([]auditEvent{create}, id, auditEvent{
		Action: actionBroker, Result: resultDeniedSSRF, AgentID: agent, GrantID: grant,
		CredID: cred, CredType: "api_key", Operation: OpHTTPRequest,
	})
	if err != nil {
		t.Fatal(err)
	}
	note, err := nextAudit([]auditEvent{create, broker}, id, auditEvent{
		Action: actionNotify, Result: resultDelivered, AgentID: agent, GrantID: grant,
		CredID: cred, CredType: "api_key", Class: ClassSSRF, RefSeq: broker.Seq,
	})
	if err != nil {
		t.Fatal(err)
	}
	if note.V != auditNoticeVersion {
		t.Fatalf("version %d", note.V)
	}
	chain := []auditEvent{create, broker, note}
	if err := verifyChain(chain); err != nil {
		t.Fatal(err)
	}
	prev := make([]byte, 32)
	v2 := eventHashV2(prev, 1, note.Time, actionNotify, id, "", "", resultDelivered, "", "", "")
	v3 := eventHashV3(prev, 1, note.Time, actionNotify, id, "", "", resultDelivered, "", "", "", ClassSSRF, 1)
	if bytes.Equal(v2, v3) {
		t.Fatal("v3 hash collapsed into v2")
	}
	reject := func(name string, events []auditEvent) {
		t.Helper()
		if err := verifyChain(events); !errors.Is(err, ErrAudit) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	changed := append([]auditEvent{}, chain...)
	changed[1].Result = resultAllowed
	reject("content", changed)
	reject("deletion", []auditEvent{chain[0], chain[2]})
	reject("reorder", []auditEvent{chain[0], chain[2], chain[1]})
	inserted := append([]auditEvent{chain[0], chain[1]}, chain[1], chain[2])
	reject("insertion", inserted)
	forged := append([]auditEvent{}, chain...)
	forged[1].Hash = strings.Repeat("00", 32)
	reject("forged hash", forged)
	linked := append([]auditEvent{}, chain...)
	linked[2].Prev = strings.Repeat("11", 32)
	reject("forged linkage", linked)
	version := append([]auditEvent{}, chain...)
	version[2].V = 4
	reject("unknown version", version)
	old := append([]auditEvent{}, chain...)
	old[2].V = auditCapabilityVersion
	reject("notice at v2", old)
	klass := append([]auditEvent{}, chain...)
	klass[2].Class = ClassRoutine
	reject("class corruption", klass)
	ref := append([]auditEvent{}, chain...)
	ref[2].RefSeq = 99
	reject("ref corruption", ref)
	v1 := chain[0]
	v1.Class = ClassSSRF
	reject("v1 class", []auditEvent{v1})
}

func TestM5NotifyContainAndViews(t *testing.T) {
	e := newBrokerEnv(t)
	sink := &MemoryNotifier{}
	if err := e.session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	const target = "https://svc.example/v1/ping"
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://127.0.0.1/latest"}, ErrDeniedSSRF)
	notes := sink.Snapshot()
	if len(notes) != 1 || notes[0].Class != ClassSSRF || notes[0].Severity != SeverityCritical {
		t.Fatalf("ssrf note %+v", notes)
	}
	rec, err := e.session.AuditBySeq(notes[0].AuditSeq, notes[0].AuditHash)
	if err != nil || rec.Result != resultDeniedSSRF || rec.Class != ClassSSRF || rec.Hash != notes[0].AuditHash {
		t.Fatalf("record %+v %v", rec, err)
	}
	if err := e.session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if len(sink.Snapshot()) != 1 {
		t.Fatal("delivered twice")
	}
	for _, g := range e.session.grants {
		if g.RevokedAt != nil {
			t.Fatal("default policy revoked a grant")
		}
	}

	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://other.example/v1/ping"}, ErrDeniedOrigin)
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodHead, Target: target}, ErrDeniedMethod)
	e.session.resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	if err := e.session.SetAbuseGuard(func(AbuseDecision) error { return errors.New(string(e.secret)) }); err != nil {
		t.Fatal(err)
	}
	e.session.httpDo = func(*http.Request) (*http.Response, error) {
		t.Fatal("rate veto reached the network")
		return nil, errors.New("network")
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: target}, ErrDeniedAbuse)
	e.session.SetAbuseGuard(nil)
	e.session.httpDo = func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusFound, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: target}, ErrDeniedRedirect)

	if err := e.session.SetResponsePolicy(ResponsePolicy{Destructive: DestructiveDeny}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.session.IssueGrant(GrantSpec{
		AgentID: e.agentID, CredentialID: e.apiID, Operations: []string{OpHTTPRequest},
		Resource: "DELETE " + target, ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	e.session.resolve = func(context.Context, string) ([]net.IP, error) {
		t.Fatal("destructive deny resolved a name")
		return nil, errors.New("dns")
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodDelete, Target: target}, ErrDeniedDestructive)
	if err := e.session.SetResponsePolicy(ResponsePolicy{}); err != nil {
		t.Fatal(err)
	}

	if _, err := e.principal.Authorize(e.apiID, "get_secret", target); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := e.principal.Authorize(e.apiID, OpHTTPRequest, string(e.secret)); !errors.Is(err, ErrDeniedScope) {
		t.Fatal(err)
	}

	other, err := e.session.CreateAgent("other")
	if err != nil {
		t.Fatal(err)
	}
	probe, err := e.session.Agent(other.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < detectionThreshold; i++ {
		res, err := probe.BrokerHTTP(HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: target})
		if !errors.Is(err, ErrDeniedAgent) || res.StatusCode != 0 {
			t.Fatalf("repeat %d %v", res.StatusCode, err)
		}
	}
	wantClass := map[string]bool{}
	var repeated bool
	for _, ev := range e.session.audit {
		if ev.Action == actionBroker && ev.AgentID == other.ID && ev.Result == resultDeniedAgent {
			if classify(e.session.audit, ev).Class == ClassRepeatedDenial {
				repeated = true
			}
		}
		wantClass[classify(e.session.audit, ev).Class] = true
	}
	if !repeated {
		t.Fatal("repeated denials stayed ordinary")
	}
	for _, class := range []string{ClassSSRF, ClassOriginMismatch, ClassPolicyViolation, ClassRate, ClassRedirectEscape, ClassDestructive, ClassSecretProbe, ClassRepeatedDenial} {
		if !wantClass[class] {
			t.Fatalf("missing class %s", class)
		}
	}

	beforeFail := len(sink.Snapshot())
	leak := randHex(t, 32)
	sink.Fail(errors.New(leak))
	e.session.resolve = func(context.Context, string) ([]net.IP, error) {
		t.Fatal("ssrf resolved")
		return nil, errors.New("dns")
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://192.88.99.2/latest"}, ErrDeniedSSRF)
	failed := 0
	var failedRef uint64
	for _, ev := range e.session.audit {
		if ev.Action == actionNotify && ev.Result == resultFailed {
			failed++
			failedRef = ev.RefSeq
		}
	}
	if failed != 1 || failedRef == 0 {
		t.Fatalf("failed notifies %d ref %d", failed, failedRef)
	}
	var securityKept bool
	for _, ev := range e.session.audit {
		if ev.Seq == failedRef && ev.Action == actionBroker && ev.Result == resultDeniedSSRF {
			securityKept = true
		}
	}
	if !securityKept {
		t.Fatal("security event missing after notify failure")
	}
	if len(sink.Snapshot()) != beforeFail+1 {
		t.Fatal("failed delivery was not attempted")
	}
	if err := e.session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	attempts := 0
	for _, ev := range e.session.audit {
		if ev.Action == actionNotify && ev.RefSeq == failedRef && ev.Result == resultAttempted {
			attempts++
		}
	}
	if attempts != notifyAttemptLimit {
		t.Fatalf("attempts %d", attempts)
	}
	calls := len(sink.Snapshot())
	if err := e.session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if len(sink.Snapshot()) != calls {
		t.Fatal("retry was not bounded")
	}

	if _, err := e.session.AuditBySeq(0, ""); !errors.Is(err, ErrAuditNotFound) {
		t.Fatal(err)
	}
	if _, err := e.session.AuditBySeq(notes[0].AuditSeq, strings.Repeat("ab", 32)); !errors.Is(err, ErrAudit) {
		t.Fatal("forged hash accepted")
	}
	page, err := e.session.AuditHistory(AuditFilter{AgentID: e.agentID, Action: actionBroker, Class: ClassSSRF, Limit: 1})
	if err != nil || len(page) != 1 || page[0].Class != ClassSSRF || page[0].AgentID != e.agentID {
		t.Fatalf("filter %+v %v", page, err)
	}
	next, err := e.session.AuditHistory(AuditFilter{AfterSeq: page[0].Seq, Class: ClassSSRF, Limit: 1})
	if err != nil || len(next) != 1 || next[0].Seq <= page[0].Seq {
		t.Fatalf("page %+v %v", next, err)
	}
	future := time.Now().UTC().Add(time.Hour)
	empty, err := e.session.AuditHistory(AuditFilter{Since: future})
	if err != nil || len(empty) != 0 {
		t.Fatalf("future %+v %v", empty, err)
	}
	credRows, err := e.session.AuditHistory(AuditFilter{CredentialID: e.apiID, Limit: 100})
	if err != nil || len(credRows) == 0 {
		t.Fatal(err)
	}
	for _, row := range credRows {
		if row.CredentialID != e.apiID {
			t.Fatal("credential filter")
		}
	}

	getGrant := ""
	postGrant := ""
	for _, g := range e.session.grants {
		if g.Resource == "GET "+target {
			getGrant = g.ID
		}
		if g.Resource == "POST https://svc.example/v1/submit" {
			postGrant = g.ID
		}
	}
	if err := e.session.SetResponsePolicy(ResponsePolicy{High: ContainSuspendGrant}); err != nil {
		t.Fatal(err)
	}
	sink.Fail(nil)
	// This destination names no grant. Containment must flag it and leave every grant alone.
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://127.0.0.1/latest"}, ErrDeniedSSRF)
	for _, g := range e.session.grants {
		if g.RevokedAt != nil {
			t.Fatal("unnamed grant revoked")
		}
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodHead, Target: target}, ErrDeniedMethod)
	var suspended bool
	for _, g := range e.session.grants {
		if g.ID == getGrant && g.RevokedAt != nil {
			suspended = true
		}
		if g.ID == postGrant && g.RevokedAt != nil {
			t.Fatal("unrelated grant revoked")
		}
	}
	if !suspended {
		t.Fatal("grant was not suspended")
	}
	contained := false
	for _, ev := range e.session.audit {
		if ev.Action == actionContain && ev.Result == resultSuspended && ev.GrantID == getGrant {
			contained = true
		}
	}
	if !contained {
		t.Fatal("containment was not audited")
	}

	if err := e.session.SetResponsePolicy(ResponsePolicy{High: ContainSuspendAgent}); err != nil {
		t.Fatal(err)
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://127.0.0.1/latest"}, ErrDeniedSSRF)
	for _, a := range e.session.agents {
		if a.ID == e.agentID && a.State != agentStateSuspended {
			t.Fatal("agent was not suspended")
		}
		if a.ID == other.ID && a.State != agentStateActive {
			t.Fatal("unrelated agent suspended")
		}
	}

	calls = len(sink.Snapshot())
	if err := e.session.SetResponsePolicy(ResponsePolicy{High: ContainFlag}); err != nil {
		t.Fatal(err)
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://[fd00::1]/"}, ErrDeniedAgent)
	if len(sink.Snapshot()) != calls {
		t.Fatal("flag notified")
	}
	flagged := false
	for _, ev := range e.session.audit {
		if ev.Action == actionContain && ev.Result == resultFlagged {
			flagged = true
		}
	}
	if !flagged {
		t.Fatal("flag was not audited")
	}

	var blob bytes.Buffer
	for _, ev := range e.session.audit {
		blob.WriteString(strings.Join([]string{ev.Action, ev.Result, ev.Class, ev.AgentID, ev.GrantID, ev.CredID, ev.CredType, ev.Operation, ev.Hash}, "\n"))
		blob.WriteByte('\n')
	}
	rawNotes, err := json.Marshal(sink.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	history, err := e.session.AuditHistory(AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	rawHistory, err := json.Marshal(history)
	if err != nil {
		t.Fatal(err)
	}
	for _, surface := range [][]byte{blob.Bytes(), rawNotes, rawHistory, e.logs.Bytes(), readAll(t, e.path)} {
		if bytes.Contains(surface, e.secret) || bytes.Contains(surface, []byte(leak)) || bytes.Contains(surface, []byte("get_secret")) {
			t.Fatal("secret or caller string reached an M5 surface")
		}
	}
	var note Notification
	for _, field := range reflect.VisibleFields(reflect.TypeOf(note)) {
		switch field.Name {
		case "Severity", "Class", "Time", "AgentID", "CredentialID", "GrantID", "Action", "Result", "AuditSeq", "AuditHash":
		default:
			t.Fatalf("notification field %s", field.Name)
		}
	}

	path, pass := e.path, append([]byte(nil), e.pass...)
	e.session.Lock()
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatalf("healthy reopen %v", err)
	}
	e.session = opened
	doc := document{Credentials: e.session.creds, Agents: e.session.agents, Grants: e.session.grants}
	plain, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	nonce, ct, err := seal(e.session.dek, plain, dataAAD(e.session.id, e.session.header.AuditHead, e.session.header.AuditSeq))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.session.db.Exec(`UPDATE vault SET data_nonce=?, encrypted_document=? WHERE id=?`, nonce, ct, e.session.id); err != nil {
		t.Fatal(err)
	}
	kept := len(e.session.audit)
	e.session.Lock()
	if _, err := Unlock(path, pass, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt detection unlock %v", err)
	}
	if _, err := VerifyAudit(path, pass); !errors.Is(err, ErrAudit) {
		t.Fatalf("corrupt detection verify %v", err)
	}
	if got := len(mustAudit(t, path)); got < kept {
		t.Fatalf("audit rows suppressed %d < %d", got, kept)
	}
}

func TestSuspendedAgentDeniesBeforeDestinationClass(t *testing.T) {
	targets := []string{
		"https://127.0.0.1/latest",
		"http://svc.example/v1/ping",
		"https://user@svc.example/v1/ping",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			e := newBrokerEnv(t)
			sink := &MemoryNotifier{}
			if err := e.session.SetNotifier(sink); err != nil {
				t.Fatal(err)
			}
			if err := e.session.SetResponsePolicy(ResponsePolicy{High: ContainSuspendAgent}); err != nil {
				t.Fatal(err)
			}
			e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://127.0.0.1/latest"}, ErrDeniedSSRF)
			if len(sink.Snapshot()) != 1 || sink.Snapshot()[0].Class != ClassSSRF {
				t.Fatal("suspension did not notify once")
			}
			e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: target}, ErrDeniedAgent)
			if len(sink.Snapshot()) != 1 {
				t.Fatal("suspended agent raised another alert")
			}
			var follow auditEvent
			for _, ev := range e.session.audit {
				if ev.Action == actionBroker && ev.AgentID == e.agentID && ev.Result == resultDeniedAgent {
					follow = ev
				}
			}
			if follow.Seq == 0 || classify(e.session.audit, follow).Severity != SeverityLow {
				t.Fatalf("follow-up %+v", follow)
			}
		})
	}
}

func TestNotifyReservesAttemptBeforeDelivery(t *testing.T) {
	e := newBrokerEnv(t)
	sink := &MemoryNotifier{}
	if err := e.session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	n := 0
	e.session.commitFault = func() error {
		n++
		if n >= 2 {
			return errors.New("full")
		}
		return nil
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://127.0.0.1/latest"}, ErrDeniedSSRF)
	if len(sink.Snapshot()) != 0 {
		t.Fatal("sink ran without a durable attempt")
	}
	for _, ev := range e.session.audit {
		if ev.Action == actionNotify {
			t.Fatal("failed reservation was audited")
		}
	}
	e.session.commitFault = nil
	if err := e.session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if len(sink.Snapshot()) != 1 || sink.Snapshot()[0].Class != ClassSSRF {
		t.Fatalf("pending %+v", sink.Snapshot())
	}
	if _, err := VerifyAudit(e.path, e.pass); err != nil {
		t.Fatal(err)
	}

	e = newBrokerEnv(t)
	sink = &MemoryNotifier{}
	if err := e.session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	n = 0
	e.session.commitFault = func() error {
		n++
		if n >= 3 {
			return errors.New("full")
		}
		return nil
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://127.0.0.1/latest"}, ErrDeniedSSRF)
	if len(sink.Snapshot()) != 1 {
		t.Fatal("outcome failure skipped the sink")
	}
	attempted := 0
	for _, ev := range e.session.audit {
		if ev.Action != actionNotify {
			continue
		}
		if ev.Result == resultDelivered || ev.Result == resultFailed {
			t.Fatalf("outcome stored after a failed write: %s", ev.Result)
		}
		if ev.Result == resultAttempted {
			attempted++
		}
	}
	if attempted != 1 {
		t.Fatalf("attempts %d", attempted)
	}
	e.session.commitFault = nil
	if err := e.session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if err := e.session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if len(sink.Snapshot()) != 2 {
		t.Fatalf("deliveries %d", len(sink.Snapshot()))
	}
	attempted = 0
	for _, ev := range e.session.audit {
		if ev.Action == actionNotify && ev.Result == resultAttempted {
			attempted++
		}
	}
	if attempted != notifyAttemptLimit {
		t.Fatalf("attempts %d", attempted)
	}
}

func TestM5TruncationAndVersion(t *testing.T) {
	e := newBrokerEnv(t)
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://127.0.0.1/latest"}, ErrDeniedSSRF)
	db := e.session.db
	var seq int64
	var hash string
	if err := db.QueryRow(`SELECT seq, hash FROM audit WHERE seq=1`).Scan(&seq, &hash); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE vault SET audit_head=?, audit_seq=?`, hash, seq); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAudit(e.path, e.pass); !errors.Is(err, ErrAudit) {
		t.Fatalf("truncated head %v", err)
	}
	var v int
	if err := db.QueryRow(`SELECT v FROM audit WHERE seq=1`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE audit SET v=9 WHERE seq=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := readAuditRows(db); !errors.Is(err, ErrAudit) {
		t.Fatalf("unknown version %v", err)
	}
	if _, err := db.Exec(`UPDATE audit SET v=? WHERE seq=1`, v); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM audit WHERE seq=2`); err != nil {
		t.Fatal(err)
	}
	if _, err := readAuditRows(db); !errors.Is(err, ErrAudit) {
		t.Fatalf("deleted row %v", err)
	}
}

func TestDetectionEvictsLeastRecent(t *testing.T) {
	var events []auditEvent
	ids := make([]string, detectionMaxAgents+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("%032x", i+1)
		events = append(events, auditEvent{
			Seq: uint64(i + 1), Action: actionBroker, Result: resultDeniedMissing, AgentID: ids[i],
		})
	}
	capped := detectionFromAudit(events)
	if err := validateDetection(capped); err != nil {
		t.Fatal(err)
	}
	if len(capped.Denials) != detectionMaxAgents {
		t.Fatalf("kept %d", len(capped.Denials))
	}
	if denialHas(capped, ids[0]) || !denialHas(capped, ids[len(ids)-1]) {
		t.Fatal("evicted the newest subject or kept the oldest")
	}
	if err := checkDetection(events, capped); err != nil {
		t.Fatal(err)
	}
	if err := checkDetection(events, detectionState{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("suppressed retained subject %v", err)
	}
	oversized := detectionState{Denials: append(append([]denialSubject{}, capped.Denials...), denialSubject{AgentID: ids[0], N: 1})}
	if err := validateDetection(oversized); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("oversized mirror %v", err)
	}
	full := detectionFromAudit(events[:detectionMaxAgents])
	if len(full.Denials) != detectionMaxAgents || !denialHas(full, ids[0]) {
		t.Fatal("ceiling dropped a subject that still fit")
	}
}

func TestM5AuditsPastDetectionCeiling(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	var oldest, newest string
	for i := 0; i < detectionMaxAgents+1; i++ {
		id := fmt.Sprintf("%032x", i+1)
		if i == 0 {
			oldest = id
		}
		newest = id
		err := session.writeAudit(auditEvent{
			Action: actionBroker, Result: resultDeniedMissing, AgentID: id, Operation: OpHTTPRequest,
		}, session.creds, session.agents, session.grants)
		if err != nil {
			t.Fatalf("denial %d: %v", i, err)
		}
	}
	if len(session.detection.Denials) != detectionMaxAgents {
		t.Fatalf("mirror %d", len(session.detection.Denials))
	}
	if denialHas(session.detection, oldest) || !denialHas(session.detection, newest) {
		t.Fatal("committed mirror evicted the newest subject")
	}
	if len(session.audit) != detectionMaxAgents+2 {
		t.Fatalf("audit rows %d", len(session.audit))
	}
	session.Lock()
	if _, err := VerifyAudit(path, pass); err != nil {
		t.Fatal(err)
	}
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(opened.Lock)
	if len(opened.detection.Denials) != detectionMaxAgents || denialHas(opened.detection, oldest) {
		t.Fatal("reopened mirror")
	}
}

func TestM5MigratesPriorAuditSchema(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	if _, err := session.CreateAgent("legacy"); err != nil {
		t.Fatal(err)
	}
	var created string
	if err := session.db.QueryRow(`SELECT hash FROM audit WHERE seq=1`).Scan(&created); err != nil {
		t.Fatal(err)
	}
	session.Lock()
	rewriteAudit(t, path, true)
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatalf("m4 unlock %v", err)
	}
	var v int
	var class, hash string
	var ref int64
	if err := opened.db.QueryRow(`SELECT v, class, ref_seq, hash FROM audit WHERE action=?`, actionAgentCreate).Scan(&v, &class, &ref, new(string)); err != nil {
		t.Fatal(err)
	}
	if v != auditCapabilityVersion || class != "" || ref != 0 {
		t.Fatalf("capability backfill v=%d class=%q ref=%d", v, class, ref)
	}
	if err := opened.db.QueryRow(`SELECT v, class, ref_seq, hash FROM audit WHERE seq=1`).Scan(&v, &class, &ref, &hash); err != nil {
		t.Fatal(err)
	}
	if v != auditVersion || class != "" || ref != 0 || hash != created {
		t.Fatalf("v1 backfill v=%d class=%q ref=%d hash changed %v", v, class, ref, hash != created)
	}
	opened.Lock()
	if _, err := VerifyAudit(path, pass); err != nil {
		t.Fatal(err)
	}
	if _, err := Unlock(path, []byte("not-the-passphrase-xxxx"), nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("wrong pass %v", err)
	}
	if _, err := VerifyAudit(path, pass); err != nil {
		t.Fatalf("verify after denial %v", err)
	}

	path1, pass1, session1 := mustCreate(t, nil)
	session1.Lock()
	rewriteAudit(t, path1, false)
	opened1, err := Unlock(path1, pass1, nil)
	if err != nil {
		t.Fatalf("m1 unlock %v", err)
	}
	t.Cleanup(opened1.Lock)
	var agentID string
	if err := opened1.db.QueryRow(`SELECT v, agent_id, grant_id, operation, class, ref_seq FROM audit WHERE seq=1`).Scan(&v, &agentID, new(string), new(string), &class, &ref); err != nil {
		t.Fatal(err)
	}
	if v != auditVersion || agentID != "" || class != "" || ref != 0 {
		t.Fatalf("m1 backfill v=%d agent=%q class=%q ref=%d", v, agentID, class, ref)
	}
	if _, err := VerifyAudit(path1, pass1); err != nil {
		t.Fatal(err)
	}
}

func TestM5AdoptsLegacyDetection(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	agent := strings.Repeat("cd", 16)
	if err := session.writeAudit(auditEvent{
		Action: actionBroker, Result: resultDeniedMissing, AgentID: agent, Operation: OpHTTPRequest,
	}, session.creds, session.agents, session.grants); err != nil {
		t.Fatal(err)
	}
	var denialHash string
	if err := session.db.QueryRow(`SELECT hash FROM audit WHERE action=?`, actionBroker).Scan(&denialHash); err != nil {
		t.Fatal(err)
	}
	plain := legacyDocument(t, document{Credentials: session.creds, Agents: session.agents, Grants: session.grants})
	nonce, ct, err := seal(session.dek, plain, dataAAD(session.id, session.header.AuditHead, session.header.AuditSeq))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.db.Exec(`UPDATE vault SET data_nonce=?, encrypted_document=? WHERE id=?`, nonce, ct, session.id); err != nil {
		t.Fatal(err)
	}
	session.Lock()
	rewriteAudit(t, path, true)
	if _, err := VerifyAudit(path, pass); err != nil {
		t.Fatalf("legacy verify %v", err)
	}
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatalf("legacy unlock %v", err)
	}
	if len(opened.detection.Denials) != 1 || !denialHas(opened.detection, agent) || opened.detection.Denials[0].N != 1 {
		t.Fatalf("adopted mirror %+v", opened.detection.Denials)
	}
	var hash string
	if err := opened.db.QueryRow(`SELECT hash FROM audit WHERE action=?`, actionBroker).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash != denialHash {
		t.Fatal("denial hash changed")
	}
	stored, err := openAEAD(opened.dek, opened.header.DataNonce, opened.header.Data, dataAAD(opened.id, opened.header.AuditHead, opened.header.AuditSeq))
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(stored)
	if !bytes.Contains(stored, []byte(`"detection"`)) {
		t.Fatal("unlock did not persist the mirror")
	}
	opened.Lock()
	reopened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatalf("second unlock %v", err)
	}
	t.Cleanup(reopened.Lock)
	if len(reopened.detection.Denials) != 1 || reopened.detection.Denials[0].N != 1 {
		t.Fatalf("persisted mirror %+v", reopened.detection.Denials)
	}
	if err := reopened.writeAudit(auditEvent{
		Action: actionBroker, Result: resultDeniedMissing, AgentID: agent, Operation: OpHTTPRequest,
	}, reopened.creds, reopened.agents, reopened.grants); err != nil {
		t.Fatal(err)
	}
	if len(reopened.detection.Denials) != 1 || reopened.detection.Denials[0].N != 2 {
		t.Fatalf("later denial %+v", reopened.detection.Denials)
	}
}

func legacyDocument(t *testing.T, doc document) []byte {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "detection")
	plain, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain, []byte(`"detection"`)) {
		t.Fatal("legacy document still has detection")
	}
	return plain
}

func TestContainmentCommitsWithTrigger(t *testing.T) {
	const target = "https://svc.example/v1/ping"
	ssrf := HTTPBrokerRequest{CredentialID: "", Method: http.MethodGet, Target: "https://127.0.0.1/latest"}

	t.Run("rollback", func(t *testing.T) {
		e := newBrokerEnv(t)
		ssrf.CredentialID = e.apiID
		sink := &MemoryNotifier{}
		if err := e.session.SetNotifier(sink); err != nil {
			t.Fatal(err)
		}
		if err := e.session.SetResponsePolicy(ResponsePolicy{High: ContainSuspendAgent}); err != nil {
			t.Fatal(err)
		}
		before := len(e.session.audit)
		head := e.session.header.AuditHead
		e.session.commitFault = func() error { return errors.New("full") }
		res, err := e.principal.BrokerHTTP(ssrf)
		if !errors.Is(err, ErrAudit) || res.StatusCode != 0 {
			t.Fatalf("status %d err %v", res.StatusCode, err)
		}
		if len(e.session.audit) != before || e.session.header.AuditHead != head {
			t.Fatal("failed transaction left a trigger")
		}
		if agentState(e.session, e.agentID) != agentStateActive {
			t.Fatal("agent suspended without a committed trigger")
		}
		if len(sink.Snapshot()) != 0 {
			t.Fatal("sink ran inside a failed transaction")
		}
		opened := reopen(t, e)
		if agentState(opened, e.agentID) != agentStateActive {
			t.Fatal("reopen showed a suspension")
		}
		for _, ev := range opened.audit {
			if ev.Action == actionBroker && ev.Result == resultDeniedSSRF {
				t.Fatal("reopen showed the trigger")
			}
			if ev.Action == actionRespond || ev.Action == actionContain {
				t.Fatal("reopen showed a response row")
			}
		}
	})

	t.Run("later write keeps suspension", func(t *testing.T) {
		e := newBrokerEnv(t)
		ssrf.CredentialID = e.apiID
		sink := &MemoryNotifier{}
		if err := e.session.SetNotifier(sink); err != nil {
			t.Fatal(err)
		}
		if err := e.session.SetResponsePolicy(ResponsePolicy{High: ContainSuspendAgent}); err != nil {
			t.Fatal(err)
		}
		n := 0
		e.session.commitFault = func() error {
			n++
			if n >= 2 {
				return errors.New("full")
			}
			return nil
		}
		e.deny(t, ssrf, ErrDeniedSSRF)
		if agentState(e.session, e.agentID) != agentStateSuspended {
			t.Fatal("trigger committed without suspension")
		}
		if !bundled(e.session.audit, resultDeniedSSRF, resultDecisionNotify, resultAgentSuspended) {
			t.Fatal("event, decision, and suspension were not one commit")
		}
		for _, ev := range e.session.audit {
			if ev.Action == actionNotify {
				t.Fatal("notification was inside the containment transaction")
			}
		}
		if len(sink.Snapshot()) != 0 {
			t.Fatal("sink ran before its attempt row committed")
		}
		if _, err := VerifyAudit(e.path, e.pass); err != nil {
			t.Fatal(err)
		}
		opened := reopen(t, e)
		if agentState(opened, e.agentID) != agentStateSuspended {
			t.Fatal("suspension did not survive reopen")
		}
		if !bundled(opened.audit, resultDeniedSSRF, resultDecisionNotify, resultAgentSuspended) {
			t.Fatal("reopen split the bundle")
		}
	})

	t.Run("grant", func(t *testing.T) {
		e := newBrokerEnv(t)
		sink := &MemoryNotifier{}
		if err := e.session.SetNotifier(sink); err != nil {
			t.Fatal(err)
		}
		if err := e.session.SetResponsePolicy(ResponsePolicy{High: ContainSuspendGrant}); err != nil {
			t.Fatal(err)
		}
		var grantID string
		for _, g := range e.session.grants {
			if g.Resource == "GET "+target {
				grantID = g.ID
			}
		}
		if grantID == "" {
			t.Fatal("missing grant")
		}
		e.session.commitFault = func() error { return errors.New("full") }
		res, err := e.principal.BrokerHTTP(HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodHead, Target: target})
		if !errors.Is(err, ErrAudit) || res.StatusCode != 0 {
			t.Fatalf("status %d err %v", res.StatusCode, err)
		}
		if grantRevoked(e.session, grantID) {
			t.Fatal("grant revoked without a committed trigger")
		}
		e.session.commitFault = nil
		e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodHead, Target: target}, ErrDeniedMethod)
		if !grantRevoked(e.session, grantID) {
			t.Fatal("grant was not suspended with the trigger")
		}
		if !bundled(e.session.audit, resultDeniedMethod, resultDecisionNotify, resultSuspended) {
			t.Fatal("grant suspension was not bundled")
		}
		opened := reopen(t, e)
		if !grantRevoked(opened, grantID) {
			t.Fatal("grant suspension did not survive reopen")
		}
		if _, err := VerifyAudit(e.path, e.pass); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDeliverPendingUsesRecordedDecision(t *testing.T) {
	e := newBrokerEnv(t)
	sink := &MemoryNotifier{}
	if err := e.session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	if err := e.session.SetResponsePolicy(ResponsePolicy{High: ContainFlag}); err != nil {
		t.Fatal(err)
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://127.0.0.1/latest"}, ErrDeniedSSRF)
	if len(sink.Snapshot()) != 0 {
		t.Fatal("flag notified")
	}
	if !hasDecision(e.session.audit, resultDecisionFlag) {
		t.Fatal("flag decision was not recorded")
	}
	if err := e.session.SetResponsePolicy(ResponsePolicy{}); err != nil {
		t.Fatal(err)
	}
	if err := e.session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if len(sink.Snapshot()) != 0 {
		t.Fatal("flag decision followed the notify policy")
	}
	opened := reopen(t, e)
	if err := opened.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	if err := opened.SetResponsePolicy(ResponsePolicy{}); err != nil {
		t.Fatal(err)
	}
	if err := opened.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if len(sink.Snapshot()) != 0 {
		t.Fatal("reopen notified a flag decision")
	}
	principal, err := opened.Agent(e.agentID)
	if err != nil {
		t.Fatal(err)
	}
	e.session = opened
	e.principal = principal

	sink.Fail(errors.New("down"))
	if err := e.session.SetResponsePolicy(ResponsePolicy{}); err != nil {
		t.Fatal(err)
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://192.88.99.2/latest"}, ErrDeniedSSRF)
	if len(sink.Snapshot()) != 1 {
		t.Fatal("notify decision did not deliver")
	}
	sink.Fail(nil)
	if err := e.session.SetResponsePolicy(ResponsePolicy{High: ContainFlag}); err != nil {
		t.Fatal(err)
	}
	if err := e.session.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if len(sink.Snapshot()) != 2 {
		t.Fatalf("flag policy suppressed a notify decision: %d", len(sink.Snapshot()))
	}
	opened = reopen(t, e)
	fresh := &MemoryNotifier{}
	if err := opened.SetNotifier(fresh); err != nil {
		t.Fatal(err)
	}
	if err := opened.SetResponsePolicy(ResponsePolicy{High: ContainFlag}); err != nil {
		t.Fatal(err)
	}
	if err := opened.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if len(fresh.Snapshot()) != 0 {
		t.Fatal("reopen retried a finished notify decision or a flag decision")
	}
	if !hasDecision(opened.audit, resultDecisionFlag) || !hasDecision(opened.audit, resultDecisionNotify) {
		t.Fatal("reopen lost a recorded decision")
	}
}

func TestSuspendedSecretProbeStaysOrdinary(t *testing.T) {
	e := newBrokerEnv(t)
	sink := &MemoryNotifier{}
	if err := e.session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	if err := e.session.SetResponsePolicy(ResponsePolicy{High: ContainSuspendAgent}); err != nil {
		t.Fatal(err)
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://127.0.0.1/latest"}, ErrDeniedSSRF)
	if len(sink.Snapshot()) != 1 {
		t.Fatal("suspension did not notify once")
	}
	const target = "https://svc.example/v1/ping"
	for i := 0; i < 3; i++ {
		if _, err := e.principal.Authorize(e.apiID, "get_secret", target); !errors.Is(err, ErrDeniedAgent) {
			t.Fatalf("probe %d: %v", i, err)
		}
	}
	if len(sink.Snapshot()) != 1 {
		t.Fatal("suspended secret probe raised another alert")
	}
	for _, ev := range e.session.audit {
		if ev.Result == resultDeniedSecret || strings.Contains(ev.Operation, "get_secret") {
			t.Fatalf("probe recorded %+v", ev)
		}
		if ev.Action == actionAuthorize && classify(e.session.audit, ev).Severity != SeverityLow {
			t.Fatalf("authorize class %+v", ev)
		}
	}
}

func TestSuspendedFollowUpsStayOrdinary(t *testing.T) {
	e := newBrokerEnv(t)
	sink := &MemoryNotifier{}
	if err := e.session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	if err := e.session.SetResponsePolicy(ResponsePolicy{High: ContainSuspendAgent}); err != nil {
		t.Fatal(err)
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://127.0.0.1/latest"}, ErrDeniedSSRF)
	if len(sink.Snapshot()) != 1 || sink.Snapshot()[0].Class != ClassSSRF {
		t.Fatal("suspension did not notify once")
	}
	// One past the lookback, so the triggering denial is outside the window.
	const target = "https://svc.example/v1/ping"
	followUps := detectionLookback + 1
	for i := 0; i < followUps; i++ {
		e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://127.0.0.1/latest"}, ErrDeniedAgent)
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: target}, ErrDeniedAgent)
	followUps++
	for i := 0; i < 3; i++ {
		if _, err := e.principal.Authorize(e.apiID, "get_secret", target); !errors.Is(err, ErrDeniedAgent) {
			t.Fatalf("probe %d: %v", i, err)
		}
	}
	if len(sink.Snapshot()) != 1 {
		t.Fatalf("follow-up raised an alert: %d", len(sink.Snapshot()))
	}
	deniedAgent := 0
	probes := 0
	for _, ev := range e.session.audit {
		class := classify(e.session.audit, ev)
		if ev.Action == actionBroker && ev.AgentID == e.agentID && ev.Result == resultDeniedAgent {
			deniedAgent++
			if class.Class != ClassExpectedDenial || class.Severity != SeverityLow {
				t.Fatalf("follow-up class %+v", class)
			}
			if responseDecision(e.session.audit, ev.Seq) != "" {
				t.Fatal("follow-up recorded a response")
			}
		}
		if ev.Action == actionAuthorize && ev.AgentID == e.agentID {
			probes++
			if ev.Result != resultDeniedAgent || class.Severity != SeverityLow || strings.Contains(ev.Operation, "get_secret") {
				t.Fatalf("authorize %+v", ev)
			}
		}
		if ev.Result == resultDeniedSSRF && class.Severity != SeverityCritical {
			t.Fatal("trigger was downgraded")
		}
	}
	if deniedAgent != followUps {
		t.Fatalf("audited follow-ups %d", deniedAgent)
	}
	if probes != 3 {
		t.Fatalf("probes %d", probes)
	}
	var window []auditEvent
	for _, ev := range e.session.audit {
		if ev.Action == actionBroker && ev.AgentID == e.agentID && brokerDenialResult(ev.Result) {
			window = append(window, ev)
		}
	}
	if len(window) > detectionLookback {
		window = window[len(window)-detectionLookback:]
	}
	gotN := 0
	for _, d := range e.session.detection.Denials {
		if d.AgentID == e.agentID {
			gotN = d.N
		}
	}
	if gotN != len(window) || gotN < detectionThreshold {
		t.Fatalf("mirror n=%d window=%d", gotN, len(window))
	}
	if _, err := VerifyAudit(e.path, e.pass); err != nil {
		t.Fatal(err)
	}
	opened := reopen(t, e)
	fresh := &MemoryNotifier{}
	if err := opened.SetNotifier(fresh); err != nil {
		t.Fatal(err)
	}
	if err := opened.SetResponsePolicy(ResponsePolicy{}); err != nil {
		t.Fatal(err)
	}
	if err := opened.DeliverPending(); err != nil {
		t.Fatal(err)
	}
	if len(fresh.Snapshot()) != 0 {
		t.Fatal("deliver pending notified a suspended follow-up")
	}
	for _, ev := range opened.audit {
		if ev.Action == actionBroker && ev.Result == resultDeniedAgent && classify(opened.audit, ev).Class != ClassExpectedDenial {
			t.Fatal("reopen promoted a suspended denial")
		}
	}

	active := newBrokerEnv(t)
	activeSink := &MemoryNotifier{}
	if err := active.session.SetNotifier(activeSink); err != nil {
		t.Fatal(err)
	}
	other, err := active.session.CreateAgent("other")
	if err != nil {
		t.Fatal(err)
	}
	probe, err := active.session.Agent(other.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < detectionThreshold; i++ {
		res, err := probe.BrokerHTTP(HTTPBrokerRequest{CredentialID: active.apiID, Method: http.MethodGet, Target: target})
		if !errors.Is(err, ErrDeniedAgent) || res.StatusCode != 0 {
			t.Fatalf("active %d status %d err %v", i, res.StatusCode, err)
		}
	}
	notes := activeSink.Snapshot()
	if len(notes) != 1 || notes[0].Class != ClassRepeatedDenial {
		t.Fatalf("active agent notes %+v", notes)
	}
	var ordinary, repeated int
	for _, ev := range active.session.audit {
		if ev.Action != actionBroker || ev.AgentID != other.ID || ev.Result != resultDeniedAgent {
			continue
		}
		switch classify(active.session.audit, ev).Class {
		case ClassExpectedDenial:
			ordinary++
		case ClassRepeatedDenial:
			repeated++
		default:
			t.Fatalf("active class %+v", ev)
		}
	}
	if ordinary != detectionThreshold-1 || repeated != 1 {
		t.Fatalf("ordinary %d repeated %d", ordinary, repeated)
	}
}

func TestSuspendedUnsupportedMethodStaysAttributed(t *testing.T) {
	e := newBrokerEnv(t)
	sink := &MemoryNotifier{}
	if err := e.session.SetNotifier(sink); err != nil {
		t.Fatal(err)
	}
	if err := e.session.SetResponsePolicy(ResponsePolicy{High: ContainSuspendAgent}); err != nil {
		t.Fatal(err)
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: "TRACE", Target: "https://svc.example/v1/ping"}, ErrInvalid)
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://127.0.0.1/latest"}, ErrDeniedSSRF)
	if len(sink.Snapshot()) != 1 {
		t.Fatal("suspension did not notify once")
	}
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: "TRACE", Target: "https://svc.example/v1/ping"}, ErrDeniedAgent)
	e.deny(t, HTTPBrokerRequest{CredentialID: string(e.secret), Method: "TRACE", Target: "https://127.0.0.1/" + string(e.secret)}, ErrDeniedAgent)
	if len(sink.Snapshot()) != 1 {
		t.Fatal("unsupported method raised another alert")
	}
	var shape, attributed, leaked int
	for _, ev := range e.session.audit {
		if ev.Action != actionBroker {
			continue
		}
		fields := strings.Join([]string{ev.CredID, ev.CredType, ev.Operation, ev.AgentID, ev.GrantID, ev.Result}, "\n")
		if strings.Contains(fields, "TRACE") || secretIn(fields, e.secret) || strings.Contains(fields, "127.0.0.1") {
			leaked++
		}
		switch ev.Result {
		case resultDenied:
			shape++
			if ev.AgentID != "" || ev.CredID != "" || ev.Operation != "" {
				t.Fatalf("active shape denial %+v", ev)
			}
		case resultDeniedAgent:
			attributed++
			class := classify(e.session.audit, ev)
			if ev.AgentID != e.agentID || class.Class != ClassExpectedDenial || class.Severity != SeverityLow {
				t.Fatalf("suspended method denial %+v class %+v", ev, class)
			}
			if responseDecision(e.session.audit, ev.Seq) != "" {
				t.Fatal("unsupported method recorded a response")
			}
			if attributed == 1 && (ev.CredID != e.apiID || ev.CredType != "api_key" || ev.Operation != OpHTTPRequest) {
				t.Fatalf("valid credential dropped %+v", ev)
			}
			if attributed == 2 && (ev.CredID != "" || ev.CredType != "" || ev.Operation != OpHTTPRequest) {
				t.Fatalf("malformed credential copied %+v", ev)
			}
		}
	}
	if shape != 1 || attributed != 2 || leaked != 0 {
		t.Fatalf("shape %d attributed %d leaked %d", shape, attributed, leaked)
	}
}

func TestLegacyDecisionDoesNotUsePolicy(t *testing.T) {
	src := auditEvent{Seq: 2, Action: actionBroker, Result: resultDeniedSSRF}
	chain := []auditEvent{src}
	if notifyChosen(chain, src.Seq) {
		t.Fatal("missing decision was delivered")
	}
	flagged := append(chain, auditEvent{Action: actionContain, Result: resultFlagged, RefSeq: src.Seq})
	if notifyChosen(flagged, src.Seq) {
		t.Fatal("legacy flag was treated as notify")
	}
	attempted := append(chain, auditEvent{Action: actionNotify, Result: resultAttempted, RefSeq: src.Seq})
	if !notifyChosen(attempted, src.Seq) {
		t.Fatal("legacy notify attempt was dropped")
	}
	decidedFlag := append(chain, auditEvent{Action: actionRespond, Result: resultDecisionFlag, RefSeq: src.Seq})
	if notifyChosen(decidedFlag, src.Seq) {
		t.Fatal("flag decision was delivered")
	}
	decidedNotify := append(chain, auditEvent{Action: actionRespond, Result: resultDecisionNotify, RefSeq: src.Seq})
	if !notifyChosen(decidedNotify, src.Seq) {
		t.Fatal("notify decision was suppressed")
	}
}

func TestLegacyNotifyAttemptAndAgentSuspension(t *testing.T) {
	const ref = uint64(2)
	legacyFailed := []auditEvent{{Action: actionNotify, Result: resultFailed, RefSeq: ref}}
	if notifyAttempts(legacyFailed, ref) != 1 {
		t.Fatalf("legacy failed counted %d", notifyAttempts(legacyFailed, ref))
	}
	modern := []auditEvent{
		{Action: actionNotify, Result: resultAttempted, RefSeq: ref},
		{Action: actionNotify, Result: resultFailed, RefSeq: ref},
	}
	if notifyAttempts(modern, ref) != 1 {
		t.Fatalf("modern pair counted %d", notifyAttempts(modern, ref))
	}
	mixed := append(append([]auditEvent{}, legacyFailed...), modern...)
	if notifyAttempts(mixed, ref) != 2 {
		t.Fatalf("legacy plus modern counted %d", notifyAttempts(mixed, ref))
	}
	delivered := []auditEvent{
		{Action: actionNotify, Result: resultAttempted, RefSeq: ref},
		{Action: actionNotify, Result: resultDelivered, RefSeq: ref},
	}
	if notifyAttempts(delivered, ref) != 1 {
		t.Fatalf("delivered pair counted %d", notifyAttempts(delivered, ref))
	}

	agent := strings.Repeat("ab", 16)
	grant := strings.Repeat("cd", 16)
	suspendedAgents := []agentRecord{{ID: agent, State: agentStateSuspended}}
	activeAgents := []agentRecord{{ID: agent, State: agentStateActive}}
	revokedAt := time.Now().UTC()
	revoked := []grantRecord{{ID: grant, AgentID: agent, RevokedAt: &revokedAt}}
	legacy := []auditEvent{
		{Seq: 1, Action: actionBroker, Result: resultDeniedSSRF, AgentID: agent},
		{Seq: 2, Action: actionContain, Result: resultSuspended, AgentID: agent, Class: ClassSSRF, RefSeq: 1},
	}
	for i := 0; i < detectionLookback; i++ {
		legacy = append(legacy, auditEvent{Seq: uint64(len(legacy) + 1), Action: actionBroker, Result: resultDeniedAgent, AgentID: agent})
	}
	if got := classifyState(legacy, legacy[len(legacy)-1], suspendedAgents, nil); got.Class != ClassExpectedDenial || got.Severity != SeverityLow {
		t.Fatalf("legacy suspension %+v", got)
	}
	withGrant := []auditEvent{
		{Seq: 1, Action: actionBroker, Result: resultDeniedSSRF, AgentID: agent, GrantID: grant},
		{Seq: 2, Action: actionContain, Result: resultSuspended, AgentID: agent, GrantID: grant, Class: ClassSSRF, RefSeq: 1},
	}
	for i := 0; i < detectionThreshold; i++ {
		withGrant = append(withGrant, auditEvent{Seq: uint64(len(withGrant) + 1), Action: actionBroker, Result: resultDeniedAgent, AgentID: agent})
	}
	if classifyState(withGrant, withGrant[len(withGrant)-1], suspendedAgents, nil).Class != ClassExpectedDenial {
		t.Fatal("active grant on a legacy agent row suppressed nothing")
	}
	grantOnly := []auditEvent{
		{Seq: 1, Action: actionBroker, Result: resultDeniedMethod, AgentID: agent, GrantID: grant},
		{Seq: 2, Action: actionContain, Result: resultSuspended, AgentID: agent, GrantID: grant, Class: ClassPolicyViolation, RefSeq: 1},
	}
	for i := 0; i < detectionThreshold; i++ {
		grantOnly = append(grantOnly, auditEvent{Seq: uint64(len(grantOnly) + 1), Action: actionBroker, Result: resultDeniedAgent, AgentID: agent})
	}
	if classifyState(grantOnly, grantOnly[len(grantOnly)-1], activeAgents, revoked).Class != ClassRepeatedDenial {
		t.Fatal("grant-only suspension hid an active agent")
	}
	if classifyState(grantOnly, grantOnly[len(grantOnly)-1], suspendedAgents, revoked).Class != ClassRepeatedDenial {
		t.Fatal("revoked grant row counted as an agent suspension")
	}
	modernHold := append([]auditEvent{}, legacy[0], auditEvent{Seq: 2, Action: actionContain, Result: resultAgentSuspended, AgentID: agent, Class: ClassSSRF, RefSeq: 1})
	modernHold = append(modernHold, legacy[2:]...)
	if classify(modernHold, modernHold[len(modernHold)-1]).Class != ClassExpectedDenial {
		t.Fatal("modern agent_suspended control regressed")
	}
}

func TestLegacyVaultRetryCapAndSuspension(t *testing.T) {
	t.Run("notify cap", func(t *testing.T) {
		e := newBrokerEnv(t)
		sink := &MemoryNotifier{}
		if err := e.session.SetNotifier(sink); err != nil {
			t.Fatal(err)
		}
		sink.Fail(errors.New("down"))
		e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://127.0.0.1/latest"}, ErrDeniedSSRF)
		var security auditEvent
		for _, ev := range e.session.audit {
			if ev.Action == actionBroker && ev.Result == resultDeniedSSRF {
				security = ev
			}
		}
		if security.Seq == 0 {
			t.Fatal("missing trigger")
		}
		before := append([]auditEvent{}, e.session.audit...)
		if notifyAttempts(before, security.Seq) != 1 {
			t.Fatalf("modern control %d", notifyAttempts(before, security.Seq))
		}
		keptHash := security.Hash
		legacy := dropAuditResult(t, before, actionNotify, resultAttempted)
		for _, ev := range legacy {
			if ev.Action == actionBroker && ev.Result == resultDeniedSSRF && ev.Hash != keptHash {
				t.Fatal("trigger hash changed")
			}
		}
		if notifyAttempts(legacy, security.Seq) != 1 {
			t.Fatalf("legacy attempts %d", notifyAttempts(legacy, security.Seq))
		}
		resealAudit(t, e, legacy)
		opened := reopen(t, e)
		if _, err := VerifyAudit(e.path, e.pass); err != nil {
			t.Fatal(err)
		}
		fresh := &MemoryNotifier{}
		fresh.Fail(errors.New("down"))
		if err := opened.SetNotifier(fresh); err != nil {
			t.Fatal(err)
		}
		if err := opened.DeliverPending(); err != nil {
			t.Fatal(err)
		}
		if len(fresh.Snapshot()) != 1 {
			t.Fatalf("legacy retry sent %d", len(fresh.Snapshot()))
		}
		if err := opened.DeliverPending(); err != nil {
			t.Fatal(err)
		}
		if len(fresh.Snapshot()) != 1 {
			t.Fatalf("legacy cap exceeded %d", len(fresh.Snapshot()))
		}
		if notifyAttempts(opened.audit, security.Seq) != notifyAttemptLimit {
			t.Fatalf("attempts %d", notifyAttempts(opened.audit, security.Seq))
		}
		again := reopen(t, brokerEnv{path: e.path, pass: e.pass, session: opened})
		quiet := &MemoryNotifier{}
		quiet.Fail(errors.New("down"))
		if err := again.SetNotifier(quiet); err != nil {
			t.Fatal(err)
		}
		if err := again.DeliverPending(); err != nil {
			t.Fatal(err)
		}
		if len(quiet.Snapshot()) != 0 {
			t.Fatal("reopen exceeded the legacy cap")
		}
	})

	t.Run("agent suspension", func(t *testing.T) {
		e := newBrokerEnv(t)
		sink := &MemoryNotifier{}
		if err := e.session.SetNotifier(sink); err != nil {
			t.Fatal(err)
		}
		if err := e.session.SetResponsePolicy(ResponsePolicy{High: ContainSuspendAgent}); err != nil {
			t.Fatal(err)
		}
		e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://127.0.0.1/latest"}, ErrDeniedSSRF)
		var triggerHash string
		changed := -1
		events := append([]auditEvent{}, e.session.audit...)
		for i := range events {
			if events[i].Action == actionBroker && events[i].Result == resultDeniedSSRF {
				triggerHash = events[i].Hash
			}
			if events[i].Action == actionContain && events[i].Result == resultAgentSuspended {
				events[i].Result = resultSuspended
				changed = i
			}
		}
		if changed < 0 || triggerHash == "" {
			t.Fatal("missing modern suspension")
		}
		if err := rehashSuffix(events, changed); err != nil {
			t.Fatal(err)
		}
		for _, ev := range events {
			if ev.Action == actionBroker && ev.Result == resultDeniedSSRF && ev.Hash != triggerHash {
				t.Fatal("trigger hash changed")
			}
			if ev.Action == actionContain && ev.Result != resultSuspended {
				t.Fatal("legacy result was not installed")
			}
		}
		if agentState(e.session, e.agentID) != agentStateSuspended {
			t.Fatal("agent state was not suspended")
		}
		resealAudit(t, e, events)
		opened := reopen(t, e)
		if _, err := VerifyAudit(e.path, e.pass); err != nil {
			t.Fatal(err)
		}
		if agentState(opened, e.agentID) != agentStateSuspended {
			t.Fatal("reopen lost the suspension")
		}
		principal, err := opened.Agent(e.agentID)
		if err != nil {
			t.Fatal(err)
		}
		fresh := &MemoryNotifier{}
		if err := opened.SetNotifier(fresh); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < detectionThreshold; i++ {
			res, err := principal.BrokerHTTP(HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://127.0.0.1/latest"})
			if !errors.Is(err, ErrDeniedAgent) || res.StatusCode != 0 {
				t.Fatalf("follow-up %d status %d err %v", i, res.StatusCode, err)
			}
		}
		if len(fresh.Snapshot()) != 0 {
			t.Fatalf("legacy suspension notified %+v", fresh.Snapshot())
		}
		page, err := opened.AuditHistory(AuditFilter{AgentID: e.agentID, Action: actionBroker, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		var follow int
		for _, row := range page {
			if row.Result != resultDeniedAgent {
				continue
			}
			follow++
			if row.Class != ClassExpectedDenial || row.Severity != SeverityLow {
				t.Fatalf("follow-up class %+v", row)
			}
		}
		if follow != detectionThreshold {
			t.Fatalf("follow-ups %d", follow)
		}
		if err := opened.DeliverPending(); err != nil {
			t.Fatal(err)
		}
		if len(fresh.Snapshot()) != 0 {
			t.Fatal("deliver pending notified a legacy suspended denial")
		}
		kept := reopen(t, brokerEnv{path: e.path, pass: e.pass, session: opened})
		for _, ev := range kept.audit {
			if ev.Action == actionBroker && ev.Result == resultDeniedAgent {
				if classifyState(kept.audit, ev, kept.agents, kept.grants).Class != ClassExpectedDenial {
					t.Fatal("reopen promoted a legacy suspended denial")
				}
			}
		}
	})
}

func dropAuditResult(t *testing.T, events []auditEvent, action, result string) []auditEvent {
	t.Helper()
	first := -1
	removed := map[uint64]struct{}{}
	var kept []auditEvent
	for i, ev := range events {
		if ev.Action == action && ev.Result == result {
			if first < 0 {
				first = i
			}
			removed[ev.Seq] = struct{}{}
			continue
		}
		kept = append(kept, ev)
	}
	if first < 0 {
		t.Fatalf("missing %s/%s", action, result)
	}
	startSeq := events[first].Seq
	oldToNew := map[uint64]uint64{}
	next := startSeq
	for i := range kept {
		if kept[i].Seq < startSeq {
			oldToNew[kept[i].Seq] = kept[i].Seq
			continue
		}
		oldToNew[kept[i].Seq] = next
		kept[i].Seq = next
		next++
	}
	for i := range kept {
		if kept[i].RefSeq == 0 {
			continue
		}
		if _, gone := removed[kept[i].RefSeq]; gone {
			t.Fatal("dropped a referenced audit row")
		}
		mapped, ok := oldToNew[kept[i].RefSeq]
		if !ok {
			t.Fatalf("dangling ref %d", kept[i].RefSeq)
		}
		kept[i].RefSeq = mapped
	}
	if err := rehashSuffix(kept, first); err != nil {
		t.Fatal(err)
	}
	return kept
}

func rehashSuffix(events []auditEvent, from int) error {
	if from < 0 {
		from = 0
	}
	for i := from; i < len(events); i++ {
		prev := make([]byte, 32)
		if i > 0 {
			decoded, err := hex.DecodeString(events[i-1].Hash)
			if err != nil || len(decoded) != 32 {
				if err == nil {
					return ErrAudit
				}
				return err
			}
			prev = decoded
		}
		events[i].Prev = hex.EncodeToString(prev)
		events[i].Hash = hex.EncodeToString(hashEvent(prev, events[i]))
	}
	return nil
}

func resealAudit(t *testing.T, e brokerEnv, events []auditEvent) {
	t.Helper()
	if err := verifyChain(events); err != nil {
		t.Fatal(err)
	}
	s := e.session
	tip := events[len(events)-1]
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM audit`); err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if err := insertAudit(tx, ev); err != nil {
			t.Fatal(err)
		}
	}
	plain, err := json.Marshal(document{
		Credentials: s.creds,
		Agents:      s.agents,
		Grants:      s.grants,
		Detection:   detectionFromAudit(events),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(plain)
	nonce, ct, err := seal(s.dek, plain, dataAAD(s.id, tip.Hash, tip.Seq))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE vault SET data_nonce=?, encrypted_document=?, audit_head=?, audit_seq=? WHERE id=?`,
		nonce, ct, tip.Hash, int64(tip.Seq), s.id); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func agentState(s *Session, id string) string {
	for _, a := range s.agents {
		if a.ID == id {
			return a.State
		}
	}
	return ""
}

func grantRevoked(s *Session, id string) bool {
	for _, g := range s.grants {
		if g.ID == id {
			return g.RevokedAt != nil
		}
	}
	return false
}

func bundled(events []auditEvent, trigger, decision, contain string) bool {
	for i := 0; i+2 < len(events); i++ {
		ev, resp, hold := events[i], events[i+1], events[i+2]
		if ev.Result != trigger || resp.Action != actionRespond || resp.Result != decision || resp.RefSeq != ev.Seq {
			continue
		}
		if hold.Action != actionContain || hold.Result != contain || hold.RefSeq != ev.Seq {
			continue
		}
		if resp.Seq != ev.Seq+1 || hold.Seq != ev.Seq+2 {
			continue
		}
		return true
	}
	return false
}

func hasDecision(events []auditEvent, result string) bool {
	for _, ev := range events {
		if ev.Action == actionRespond && ev.Result == result {
			return true
		}
	}
	return false
}

func reopen(t *testing.T, e brokerEnv) *Session {
	t.Helper()
	path, pass := e.path, append([]byte(nil), e.pass...)
	e.session.Lock()
	opened, err := Unlock(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(opened.Lock)
	return opened
}

func denialHas(st detectionState, id string) bool {
	for _, d := range st.Denials {
		if d.AgentID == id {
			return true
		}
	}
	return false
}

func rewriteAudit(t *testing.T, path string, capability bool) {
	t.Helper()
	dsn, err := sqliteDSN(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cols := `seq, time, action, vault_id, credential_id, credential_type, result, prev_hash, hash`
	schema := `CREATE TABLE audit (
  seq INTEGER PRIMARY KEY,
  time TEXT NOT NULL,
  action TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  credential_type TEXT NOT NULL,
  result TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL`
	if capability {
		cols += `, agent_id, grant_id, operation`
		schema += `,
  agent_id TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  operation TEXT NOT NULL`
	}
	schema += `,
  FOREIGN KEY (vault_id) REFERENCES vault(id)
)`
	steps := []string{
		`CREATE TABLE audit_legacy AS SELECT ` + cols + ` FROM audit`,
		`DROP TABLE audit`,
		schema,
		`INSERT INTO audit (` + cols + `) SELECT ` + cols + ` FROM audit_legacy`,
		`DROP TABLE audit_legacy`,
	}
	for _, step := range steps {
		if _, err := db.Exec(step); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
	}
}

func TestSealedDetectionDoesNotCopyCredentials(t *testing.T) {
	stored := detectionState{Denials: []denialSubject{{AgentID: strings.Repeat("ab", 16), N: 1}}}
	cases := []struct {
		name string
		body string
		want detectionState
	}{
		{name: "absent", body: `{"credentials":[]}`, want: detectionState{}},
		{name: "null", body: `{"detection":null}`, want: stored},
		{name: "empty", body: `{"detection":{}}`, want: stored},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sealedDetection([]byte(tc.body), nil, stored)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("mirror %+v", got)
			}
		})
	}
	if _, err := sealedDetection([]byte(`{`), nil, stored); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("truncated %v", err)
	}

	secret := bytes.Repeat([]byte("k"), 256*1024)
	payload, err := json.Marshal(map[string]any{
		"credentials": []any{map[string]any{"secret": secret}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(payload)
	if _, err := sealedDetection([]byte(`{"detection":{}}`), nil, stored); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := sealedDetection(payload, nil, stored); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64*1024 {
		t.Fatalf("detection probe retained %d bytes of credential JSON", grew)
	}
}

func TestVerifyAuditWipesPartialDecode(t *testing.T) {
	path, pass, session := mustCreate(t, nil)
	secret := []byte(randHex(t, 24))
	if _, err := session.Put("api", "api_key", secret, PutOptions{}); err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(document{Credentials: session.creds})
	if err != nil || len(plain) == 0 || plain[len(plain)-1] != '}' {
		t.Fatalf("document %v", err)
	}
	plain = append(plain[:len(plain)-1], []byte(`,"bogus":1}`)...)
	nonce, ct, err := seal(session.dek, plain, dataAAD(session.id, session.header.AuditHead, session.header.AuditSeq))
	if err != nil {
		t.Fatal(err)
	}
	wipe(plain)
	if _, err := session.db.Exec(`UPDATE vault SET data_nonce=?, encrypted_document=? WHERE id=?`, nonce, ct, session.id); err != nil {
		t.Fatal(err)
	}
	session.Lock()
	var held []byte
	wipedSecret = func(b []byte) {
		if bytes.Equal(b, secret) {
			held = b
		}
	}
	t.Cleanup(func() { wipedSecret = nil })
	if _, err := VerifyAudit(path, pass); !errors.Is(err, ErrAudit) {
		t.Fatalf("verify %v", err)
	}
	if len(held) != len(secret) {
		t.Fatal("partially decoded credential was not observed")
	}
	for _, b := range held {
		if b != 0 {
			t.Fatal("partially decoded credential survived verify")
		}
	}
}

func TestFailedUnlockWipesDecodedCredentials(t *testing.T) {
	cases := []struct {
		name  string
		alter func(*document)
	}{
		{
			name: "detection mismatch",
			alter: func(doc *document) {
				doc.Detection = detectionState{Denials: []denialSubject{{AgentID: strings.Repeat("ab", 16), N: 1}}}
			},
		},
		{
			name: "invalid document",
			alter: func(doc *document) {
				doc.Credentials[0].Type = "not-a-type"
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, pass, session := mustCreate(t, nil)
			secret := []byte(randHex(t, 24))
			if _, err := session.Put("api", "api_key", secret, PutOptions{}); err != nil {
				t.Fatal(err)
			}
			doc := document{Credentials: session.creds}
			tc.alter(&doc)
			plain, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			nonce, ct, err := seal(session.dek, plain, dataAAD(session.id, session.header.AuditHead, session.header.AuditSeq))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := session.db.Exec(`UPDATE vault SET data_nonce=?, encrypted_document=? WHERE id=?`, nonce, ct, session.id); err != nil {
				t.Fatal(err)
			}
			session.Lock()
			var got []byte
			unlockDecoded = func(creds []credential) {
				if len(creds) == 1 {
					got = creds[0].Secret
				}
			}
			t.Cleanup(func() { unlockDecoded = nil })
			if _, err := Unlock(path, pass, nil); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("unlock %v", err)
			}
			if len(got) != len(secret) {
				t.Fatal("decoded credential was not observed")
			}
			for _, b := range got {
				if b != 0 {
					t.Fatal("decoded credential survived a failed unlock")
				}
			}
		})
	}
}
