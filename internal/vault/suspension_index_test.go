package vault

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDeniedAgentCommitsDoNotScanHistory(t *testing.T) {
	e := newBrokerEnv(t)
	bare, err := e.session.CreateAgent("no grants")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := e.session.Agent(bare.ID)
	if err != nil {
		t.Fatal(err)
	}
	req := HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://svc.example/v1/ping"}
	// Exercise the actual broker/judge/commit path, not a fabricated result code.
	for i := 0; i < 512; i++ {
		before := len(e.session.audit)
		auditPrefixScans = 0
		suspensionApplyVisits.Store(0)
		if _, err := principal.BrokerHTTP(req); !errors.Is(err, ErrDeniedAgent) {
			t.Fatal(err)
		}
		if auditPrefixScans != 0 {
			t.Fatalf("denial %d scanned %d historical rows", i, auditPrefixScans)
		}
		if got, want := suspensionApplyVisits.Load(), int64(len(e.session.audit)-before); got != want {
			t.Fatalf("applied %d rows, wrote %d", got, want)
		}
		ev := e.session.audit[before]
		if ev.Result != resultDeniedAgent || ev.AgentID != bare.ID {
			t.Fatalf("wrong broker row %+v", ev)
		}
		if i >= 2 && e.session.notices[ev.Seq].class != ClassRepeatedDenial {
			t.Fatal("active agent's denials failed to promote")
		}
	}
	if len(e.session.suspensions.modern) != 0 || len(e.session.suspensions.legacy) != 0 {
		t.Fatal("denial traffic grew suspension state")
	}
	opened := reopen(t, e)
	principal, err = opened.Agent(bare.ID)
	if err != nil {
		t.Fatal(err)
	}
	auditPrefixScans = 0
	if _, err = principal.BrokerHTTP(req); !errors.Is(err, ErrDeniedAgent) {
		t.Fatal(err)
	}
	if auditPrefixScans != 0 {
		t.Fatal("reopened incoming denial rescanned history")
	}
}

func TestSuspensionIndexPreservesLegacyStateInterpretation(t *testing.T) {
	agent, other, grant := strings.Repeat("ab", 16), strings.Repeat("bc", 16), strings.Repeat("cd", 16)
	now := time.Now().UTC()
	cases := []struct {
		name        string
		result      string
		ref         uint64
		sourceAgent string
		sourceGrant string
		rowGrant    string
		state       string
		revoked     bool
		explicit    bool
		want        bool
	}{
		{"modern", resultAgentSuspended, 1, agent, "", "", agentStateActive, false, false, true},
		{"legacy suspended", resultSuspended, 1, agent, "", "", agentStateSuspended, false, false, true},
		{"legacy active", resultSuspended, 1, agent, "", "", agentStateActive, false, false, false},
		{"grant only", resultSuspended, 1, agent, grant, grant, agentStateSuspended, true, false, false},
		{"explicit revocation", resultSuspended, 1, agent, grant, grant, agentStateSuspended, true, true, true},
		{"source grant fallback", resultSuspended, 1, agent, grant, "", agentStateSuspended, true, false, false},
		{"wrong source agent", resultSuspended, 1, other, "", "", agentStateSuspended, false, false, false},
		{"missing ref", resultSuspended, 0, agent, "", "", agentStateSuspended, false, false, false},
		{"future ref", resultSuspended, 9, agent, "", "", agentStateSuspended, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := []auditEvent{
				{Seq: 1, Action: actionBroker, Result: resultDeniedSSRF, AgentID: tc.sourceAgent, GrantID: tc.sourceGrant},
				{Seq: 2, Action: actionContain, Result: tc.result, AgentID: agent, GrantID: tc.rowGrant, RefSeq: tc.ref},
			}
			agents := []agentRecord{{ID: agent, State: tc.state}}
			grants := []grantRecord{{ID: grant}}
			if tc.revoked {
				grants[0].RevokedAt = &now
			}
			idx := suspensionFromAudit(events)
			if tc.explicit {
				ev := auditEvent{Seq: 3, Action: actionGrantRevoke, Result: resultAllowed, GrantID: grant}
				events = append(events, ev)
				idx.apply(events, ev)
			}
			session := &Session{audit: events, suspensions: idx}
			got := session.incomingAgentSuspended(agent, agents, grants)
			want := agentSuspendedBefore(events, agent, uint64(len(events)+1), agents, grants)
			if got != want || got != tc.want {
				t.Fatalf("indexed %v historical %v expected %v", got, want, tc.want)
			}
			// Legacy decisions must not be frozen when authenticated agent state changes.
			if tc.name == "legacy suspended" {
				agents[0].State = agentStateActive
				if session.incomingAgentSuspended(agent, agents, grants) {
					t.Fatal("cached a legacy classification")
				}
			}
		})
	}
}

func TestSuspensionIndexRollbackAndReopen(t *testing.T) {
	e := newBrokerEnv(t)
	if err := e.session.SetResponsePolicy(ResponsePolicy{High: ContainSuspendAgent}); err != nil {
		t.Fatal(err)
	}
	req := HTTPBrokerRequest{CredentialID: e.apiID, Method: http.MethodGet, Target: "https://127.0.0.1/latest"}
	e.session.commitFault = func() error { return errors.New("storage unavailable") }
	if _, err := e.session.brokerHTTP(e.agentID, req); err == nil {
		t.Fatal("faulted suspension succeeded")
	}
	if e.session.suspensions.modern[e.agentID] {
		t.Fatal("failed transaction published suspension")
	}
	e.session.commitFault = nil
	e.deny(t, req, ErrDeniedSSRF)
	if !e.session.suspensions.modern[e.agentID] {
		t.Fatal("committed suspension missing")
	}
	want := suspensionFromAudit(e.session.audit)
	if !reflect.DeepEqual(e.session.suspensions, want) {
		t.Fatal("incremental index differs from rebuild")
	}
	opened := reopen(t, e)
	if !reflect.DeepEqual(opened.suspensions, want) {
		t.Fatal("reopen lost suspension")
	}
	auditPrefixScans = 0
	if _, err := opened.brokerHTTP(e.agentID, req); !errors.Is(err, ErrDeniedAgent) {
		t.Fatal(err)
	}
	if auditPrefixScans != 0 {
		t.Fatal("suspended incoming denial scanned history")
	}
}

func TestLegacySuspensionIndexTracksGrantChangesAndDeduplicates(t *testing.T) {
	agent, grant := strings.Repeat("ef", 16), strings.Repeat("ab", 16)
	events := []auditEvent{{Seq: 1, Action: actionBroker, Result: resultDeniedSSRF, AgentID: agent, GrantID: grant}}
	idx := newSuspensionIndex()
	for i := 0; i < 512; i++ {
		row := auditEvent{Seq: uint64(len(events) + 1), Action: actionContain, Result: resultSuspended, AgentID: agent, GrantID: grant, RefSeq: 1}
		events = append(events, row)
		idx.apply(events, row)
	}
	if len(idx.legacy) != 1 || len(idx.legacy[agent]) != 1 {
		t.Fatal("duplicate legacy rows grew index")
	}
	session := &Session{audit: events, suspensions: idx}
	agents := []agentRecord{{ID: agent, State: agentStateSuspended}}
	grants := []grantRecord{{ID: grant}}
	if !session.incomingAgentSuspended(agent, agents, grants) {
		t.Fatal("legacy suspension missing")
	}
	now := time.Now().UTC()
	grants[0].RevokedAt = &now
	if session.incomingAgentSuspended(agent, agents, grants) {
		t.Fatal("grant-only containment retained stale suppression")
	}
	row := auditEvent{Seq: uint64(len(events) + 1), Action: actionGrantRevoke, Result: resultAllowed, GrantID: grant}
	events = append(events, row)
	idx.apply(events, row)
	if !session.incomingAgentSuspended(agent, agents, grants) {
		t.Fatal("explicit revocation did not restore legacy interpretation")
	}
	if !reflect.DeepEqual(idx, suspensionFromAudit(events)) {
		t.Fatal("legacy incremental index differs from rebuild")
	}
}
