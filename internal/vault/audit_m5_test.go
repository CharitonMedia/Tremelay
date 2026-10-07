package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"reflect"
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
		{auditEvent{Action: actionContain, Result: resultSuspended, Class: ClassSSRF}, Classification{ClassNotice, SeverityInfo}},
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
	failed = 0
	for _, ev := range e.session.audit {
		if ev.Action == actionNotify && ev.RefSeq == failedRef {
			failed++
		}
	}
	if failed != notifyAttemptLimit {
		t.Fatalf("attempts %d", failed)
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
	e.deny(t, HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://[fd00::1]/"}, ErrDeniedSSRF)
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
