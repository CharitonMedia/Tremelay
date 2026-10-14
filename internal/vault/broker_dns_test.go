package vault

import (
	"context"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// Agent A blocked in DNS resolution must not hold the session mutex: agent B's
// catalogue list and the owner's Lock must proceed concurrently.
func TestBrokerDNSDoesNotHoldSessionMutex(t *testing.T) {
	e := newMCPNetworkEnv(t)
	capA := bindCap(t, e.s, e.agent.ID)
	agentB, err := e.s.CreateAgent("peer-" + randHex(t, 8))
	if err != nil {
		t.Fatal(err)
	}
	capB := bindCap(t, e.s, agentB.ID)

	listA := capCall(t, capA, okBytes(t)(encodeCapList()))
	var handle [32]byte
	for _, entry := range listA.entries {
		if entry.operation == OpHTTPBroker {
			handle = entry.handle
			break
		}
	}
	msg, err := encodeBrokerInvoke(handle, HTTPRequest{Method: http.MethodGet, Path: e.reqPath, Query: e.query})
	if err != nil {
		t.Fatal(err)
	}

	var entered sync.Once
	inResolve := make(chan struct{})
	release := make(chan struct{})
	e.s.resolve = func(context.Context, string) ([]net.IP, error) {
		entered.Do(func() { close(inResolve) })
		<-release
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}

	done := make(chan error, 1)
	go func() {
		_, err := capA.Exchange(msg)
		done <- err
	}()

	select {
	case <-inResolve:
	case <-time.After(5 * time.Second):
		t.Fatal("invoke did not reach DNS resolution")
	}

	start := time.Now()
	capCall(t, capB, okBytes(t)(encodeCapList()))
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Fatalf("agent B list blocked for %v while agent A was in DNS", elapsed)
	}

	lockDone := make(chan struct{})
	go func() {
		e.s.Lock()
		close(lockDone)
	}()
	select {
	case <-lockDone:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("owner Lock blocked while agent A was in DNS")
	}

	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("invoke did not finish after DNS release")
	}
}

func TestBrokerDNSRevokedDuringLookupRefused(t *testing.T) {
	e := newMCPNetworkEnv(t)
	cap := bindCap(t, e.s, e.agent.ID)
	list := capCall(t, cap, okBytes(t)(encodeCapList()))
	var handle [32]byte
	for _, entry := range list.entries {
		if entry.operation == OpHTTPBroker {
			handle = entry.handle
			break
		}
	}
	msg, err := encodeBrokerInvoke(handle, HTTPRequest{Method: http.MethodGet, Path: e.reqPath, Query: e.query})
	if err != nil {
		t.Fatal(err)
	}
	var entered sync.Once
	inResolve := make(chan struct{})
	release := make(chan struct{})
	e.s.resolve = func(context.Context, string) ([]net.IP, error) {
		entered.Do(func() { close(inResolve) })
		<-release
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}

	done := make(chan capResponse, 1)
	go func() {
		raw, err := cap.Exchange(msg)
		if err != nil {
			done <- capResponse{code: err.Error()}
			return
		}
		resp, err := decodeCapResponse(raw)
		if err != nil {
			done <- capResponse{code: err.Error()}
			return
		}
		done <- resp
	}()

	select {
	case <-inResolve:
	case <-time.After(5 * time.Second):
		t.Fatal("invoke did not reach DNS resolution")
	}
	if err := e.s.RevokeGrant(e.grants[OpHTTPBroker].ID); err != nil {
		t.Fatal(err)
	}
	before := len(mcpAuditSnapshot(e.s))
	close(release)

	select {
	case resp := <-done:
		if resp.code != capDeniedRevoked {
			t.Fatalf("revoked during lookup: %+v", resp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("invoke did not finish after DNS release")
	}
	rows := mcpNetworkBrokerRows(t, e.s, before)
	if len(rows) != 1 || rows[0].Result != resultDeniedRevoked || rows[0].GrantID != e.grants[OpHTTPBroker].ID || rows[0].Operation != OpHTTPBroker {
		t.Fatal("revoked-during-lookup denial was not audited on the bound grant")
	}
	if e.calls != 0 {
		t.Fatal("revoked grant reached the upstream after DNS")
	}
}

// TestBrokerRequestRevokedDuringLookupRefused covers the AgentPrincipal path,
// which has no bound handle: the decision is taken again after DNS.
func TestBrokerRequestRevokedDuringLookupRefused(t *testing.T) {
	e := newHTTPBrokerEnv(t, InjectBearer, "")
	entered, release := make(chan struct{}), make(chan struct{})
	e.s.resolve = func(context.Context, string) ([]net.IP, error) {
		close(entered)
		<-release
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	done := make(chan error, 1)
	go func() {
		_, err := e.principal.BrokerRequest(e.request(brokerTestPrefix))
		done <- err
	}()
	<-entered
	if err := e.s.RevokeGrant(e.grant.ID); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("grant revoked during DNS was still used")
	}
	if e.requests != 0 {
		t.Fatalf("upstream saw %d requests after revoke", e.requests)
	}
}
