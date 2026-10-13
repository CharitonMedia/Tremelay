package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func sshMCPHandle(t *testing.T, client *mcpSession) string {
	t.Helper()
	entries := entriesOf(t, mustCall(t, client, toolList, map[string]any{}))
	if len(entries) != 1 || entries[0]["operation"] != OpSSHUserAuth || len(entries[0]) != 5 {
		t.Fatal("SSH catalogue disclosed extra authority or omitted its sole capability")
	}
	h := entries[0]["handle"].(string)
	desc := toolObject(t, mustCall(t, client, toolDescribe, map[string]any{"handle": h}))
	if len(desc) != 5 || desc["handle"] != h || desc["key_id"] != nil {
		t.Fatal("SSH describe disclosed key identity before host binding")
	}
	return h
}
func sshMCPCall(t *testing.T, client *mcpSession, handle string, body []byte) []byte {
	t.Helper()
	result := mustCall(t, client, toolInvoke, invokeArgs(handle, body))
	if result.IsError {
		t.Fatal("SSH message did not produce a protocol response")
	}
	obj := toolObject(t, result)
	if len(obj) != 1 {
		t.Fatal("SSH response was not the closed one-field projection")
	}
	text, ok := obj["ssh_response"].(string)
	if !ok {
		t.Fatal("missing SSH response")
	}
	response, ok := canonicalB64Range(text, 1, 88)
	if !ok || !validCapSSHResponse(response) {
		t.Fatal("invalid SSH response projection")
	}
	return response
}

func TestMCPSSHAuthenticationBridge(t *testing.T) {
	for _, revision := range []string{mcpProtocolRevision, mcpStdio20250618, mcpStdio20251125} {
		t.Run(revision, func(t *testing.T) {
			env := newSSHEnv(t)
			client := mcpNetworkClient(t, bindCap(t, env.session, env.agent.ID), revision)
			handle := sshMCPHandle(t, client)
			before := len(mcpAuditSnapshot(env.session))
			if got := sshMCPCall(t, client, handle, []byte{sshAgentRequestIdentities}); !bytes.Equal(got, sshEmptyIdentities()) {
				t.Fatal("identity escaped before host binding")
			}
			sid := env.sessionID(32)
			bind := env.bindBody(sid, env.hostBlob, env.hostSig(env.hostPriv, sid), 0)
			if got := sshMCPCall(t, client, handle, bind); !bytes.Equal(got, []byte{sshAgentSuccess}) {
				t.Fatal("valid host proof denied")
			}
			if got := sshMCPCall(t, client, handle, []byte{sshAgentRequestIdentities}); !bytes.Equal(got, sshIdentities(env.userBlob)) {
				t.Fatal("bound identity mismatch")
			}
			preimage := env.preimage(sid, env.user, env.userBlob, env.hostBlob)
			sig := signatureRaw(t, sshMCPCall(t, client, handle, env.signBody(env.userBlob, preimage, 0)))
			if !ed25519.Verify(env.userPub, preimage, sig) {
				t.Fatal("independent SSH signature verification failed")
			}
			for _, body := range [][]byte{
				bind, env.signBody(env.userBlob, env.preimage(env.sessionID(32), env.user, env.userBlob, env.hostBlob), 0),
				env.signBody(env.userBlob, env.preimage(sid, env.user+"-other", env.userBlob, env.hostBlob), 0),
				env.signBody(env.userBlob, env.preimage(sid, env.user, env.userBlob, env.userBlob), 0),
				env.signBody(env.userBlob, env.methodPreimage(sid, "publickey"), 0),
				env.signBody(env.userBlob, preimage, 1), []byte{17, 1, 2, 3},
			} {
				if got := sshMCPCall(t, client, handle, body); !bytes.Equal(got, []byte{sshAgentFailure}) {
					t.Fatal("unauthorized SSH operation succeeded")
				}
			}
			rows := mcpAuditSnapshot(env.session)[before:]
			allowed, completed, denied := 0, 0, 0
			for _, row := range rows {
				if row.Action != actionSSHUserAuth || row.AgentID != env.agent.ID || row.GrantID != env.grant.ID || row.CredID != env.cred.ID {
					t.Fatal("SSH audit lost exact authority")
				}
				switch row.Result {
				case resultAllowed:
					allowed++
				case resultCompleted:
					completed++
				case resultDenied:
					denied++
				}
			}
			if allowed != 3 || completed != 1 || denied != 8 {
				t.Fatalf("SSH audit counts %d/%d/%d", allowed, completed, denied)
			}
			auditBytes, err := json.Marshal(rows)
			if err != nil {
				t.Fatal(err)
			}
			assertNoSecrets(t, auditBytes, [][]byte{env.der, env.hostBlob, []byte(env.user), sid, preimage, sig, []byte(handle)})
			if _, err := VerifyAudit(env.path, env.pass); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMCPSSHExactAuthority(t *testing.T) {
	for _, change := range []string{"revoked", "expired", "changed-generation-same-key", "suspended"} {
		t.Run(change, func(t *testing.T) {
			env := newSSHEnv(t)
			// A live duplicate must never rescue the selected exact handle.
			_, err := env.session.IssueGrant(GrantSpec{AgentID: env.agent.ID, CredentialID: env.cred.ID, Operations: []string{OpSSHUserAuth}, Resource: env.resource, ExpiresAt: env.grant.ExpiresAt.Add(time.Hour), SSHUsername: env.user, SSHHostKey: env.hostBlob})
			if err != nil {
				t.Fatal(err)
			}
			cap := bindCap(t, env.session, env.agent.ID)
			client := startStdioSDK(t, cap, mcpStdio20251125)
			entries := entriesOf(t, mustCall(t, client, toolList, map[string]any{}))
			var handle string
			for _, entry := range entries {
				var raw [32]byte
				copy(raw[:], mustB64(t, entry["handle"].(string)))
				bound, _ := cap.lookup(raw)
				if bound.grantID == env.grant.ID {
					handle = entry["handle"].(string)
				}
			}
			if handle == "" {
				t.Fatal("missing exact handle")
			}
			sid := env.sessionID(32)
			if got := sshMCPCall(t, client, handle, env.bindBody(sid, env.hostBlob, env.hostSig(env.hostPriv, sid), 0)); !bytes.Equal(got, []byte{sshAgentSuccess}) {
				t.Fatal("bind")
			}
			want := resultDeniedRevoked
			switch change {
			case "revoked":
				if err := env.session.RevokeGrant(env.grant.ID); err != nil {
					t.Fatal(err)
				}
			case "expired":
				env.session.clock = func() time.Time { return env.grant.ExpiresAt }
				want = resultDeniedExpired
			case "changed-generation-same-key":
				_, next := mustEd25519(t)
				if _, err := env.session.Replace(env.cred.ID, derPlaceholder(t, next), LifecycleOptions{}); err != nil {
					t.Fatal(err)
				}
				if _, err := env.session.Replace(env.cred.ID, env.der, LifecycleOptions{}); err != nil {
					t.Fatal(err)
				}
				want = resultDeniedKey
			case "suspended":
				for i := range env.session.agents {
					if env.session.agents[i].ID == env.agent.ID {
						env.session.agents[i].State = agentStateSuspended
					}
				}
				want = resultDeniedAgent
			}
			before := len(mcpAuditSnapshot(env.session))
			body := env.signBody(env.userBlob, env.preimage(sid, env.user, env.userBlob, env.hostBlob), 0)
			if got := sshMCPCall(t, client, handle, body); !bytes.Equal(got, []byte{sshAgentFailure}) {
				t.Fatal("changed authority signed")
			}
			rows := mcpAuditSnapshot(env.session)[before:]
			wantRows := 1
			if change == "revoked" {
				wantRows = 2
			}
			if len(rows) != wantRows || rows[0].Action != actionSSHUserAuth || rows[0].Result != want || rows[0].GrantID != env.grant.ID {
				t.Fatalf("authority denial audit: %+v", rows)
			}
			if change == "revoked" && (rows[1].Action != actionRespond || rows[1].Class != "replay" || rows[1].RefSeq != rows[0].Seq) {
				t.Fatal("revoked SSH denial lost replay response control")
			}
		})
	}
}

func TestMCPSSHShapeAndIsolation(t *testing.T) {
	env := newSSHEnv(t)
	cap := bindCap(t, env.session, env.agent.ID)
	client := startStdioSDK(t, cap, mcpStdio20251125)
	handle := sshMCPHandle(t, client)
	for _, payload := range [][]byte{nil, bytes.Repeat([]byte{1}, MaxSSHFrame+1)} {
		before := len(mcpAuditSnapshot(env.session))
		args := map[string]any{"handle": handle}
		if payload != nil {
			args = invokeArgs(handle, payload)
		}
		result := mustCall(t, client, toolInvoke, args)
		if !result.IsError || toolObject(t, result)["code"] != capMalformed {
			t.Fatal("SSH outer shape accepted")
		}
		assertSparse(t, env.session, before, actionAgentCap)
	}
	// A foreign adapter and another principal cannot use this handle.
	foreign := bindCap(t, env.session, env.agent.ID)
	agent, err := env.session.CreateAgent("another-ssh-agent")
	if err != nil {
		t.Fatal(err)
	}
	other := bindCap(t, env.session, agent.ID)
	var h [32]byte
	copy(h[:], mustB64(t, handle))
	for _, a := range []*AgentCapability{foreign, other} {
		before := len(mcpAuditSnapshot(env.session))
		out := capCall(t, a, okBytes(t)(encodeCapInvoke(h, []byte{sshAgentRequestIdentities})))
		if out.code != capUnknownHandle {
			t.Fatal("foreign handle accepted")
		}
		assertSparse(t, env.session, before, actionAgentCap)
	}
	// A raw Exchange caller cannot create or borrow MCP-owned stream state.
	before := len(mcpAuditSnapshot(env.session))
	out := capCall(t, cap, okBytes(t)(encodeCapInvoke(h, []byte{sshAgentRequestIdentities})))
	if out.code != capDenied {
		t.Fatal("raw Exchange gained stateful SSH")
	}
	rows := mcpAuditSnapshot(env.session)[before:]
	if len(rows) != 1 || rows[0].Action != actionSSHUserAuth || rows[0].Result != resultDenied {
		t.Fatal("raw SSH denial not audited")
	}
}

// Reuse one endpoint, with ordinary unblocked in-memory I/O and explicit joins.
// This is not a blocked-output or callback cancellation probe.
func startJoinedSSHSDK(t *testing.T, ep *MCPEndpoint) (*mcpSession, func()) {
	t.Helper()
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan error, 1)
	go func() { done <- ep.Serve(ctx, sr, sw) }()
	logs := &mcpLog{}
	c := mcp.NewClient(&mcp.Implementation{Name: "ssh-synthetic-client", Version: "1"}, &mcp.ClientOptions{Logger: slog.New(logs), MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true}})
	cs, err := c.Connect(ctx, &mcp.IOTransport{Reader: cr, Writer: cw, MaxLineLength: maxMCPFrame + 1}, &mcp.ClientSessionOptions{ProtocolVersion: mcpStdio20251125})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			_ = cs.Close()
			cancel()
			_ = cr.Close()
			_ = cw.Close()
			select {
			case err := <-done:
				if err != nil && err != context.Canceled {
					t.Error(err)
				}
			case <-time.After(5 * time.Second):
				t.Error("SSH epoch did not join")
			}
		})
	}
	t.Cleanup(closeAll)
	waitMCPIdle(t, ep)
	return &mcpSession{ep: ep, cs: cs, clientLog: logs, cancel: cancel}, closeAll
}

func TestMCPSSHEpochLifetime(t *testing.T) {
	env := newSSHEnv(t)
	cap := bindCap(t, env.session, env.agent.ID)
	ep := stdioEndpoint(t, cap)
	client, stop := startJoinedSSHSDK(t, ep)
	handle := sshMCPHandle(t, client)
	var h [32]byte
	copy(h[:], mustB64(t, handle))
	sid := env.sessionID(32)
	bind := env.bindBody(sid, env.hostBlob, env.hostSig(env.hostPriv, sid), 0)
	if got := sshMCPCall(t, client, handle, bind); !bytes.Equal(got, []byte{sshAgentSuccess}) {
		t.Fatal("bind")
	}
	// Exercise exact cancellation state directly, without blocking output or
	// executing a callback: an unrelated ID must not retire this SSH stream.
	bound, _ := cap.lookup(h)
	ep.mu.Lock()
	epoch := ep.sshEpoch
	ep.beginCallLocked(callKey{num: 71, isNum: true}, true)
	ep.callSSH = &bound
	ep.callSSHHandle = h
	ep.mu.Unlock()
	if ep.acceptCancel(callKey{num: 72, isNum: true}) || !epoch.usable(h) {
		t.Fatal("unmatched cancellation retired another handle")
	}
	if !ep.acceptCancel(callKey{num: 71, isNum: true}) || epoch.usable(h) {
		t.Fatal("matching cancellation did not retire stream")
	}
	ep.mu.Lock()
	ep.finishCallLocked(callKey{num: 71, isNum: true})
	ep.mu.Unlock()
	result := mustCall(t, client, toolInvoke, invokeArgs(handle, bind))
	if !result.IsError || toolObject(t, result)["code"] != capDenied {
		t.Fatal("retired handle restarted")
	}
	stop()
	if epoch.slots != nil {
		t.Fatal("joined epoch retained stream state")
	}
	client2, stop2 := startJoinedSSHSDK(t, ep)
	defer stop2()
	if got := sshMCPCall(t, client2, handle, []byte{sshAgentRequestIdentities}); !bytes.Equal(got, sshEmptyIdentities()) {
		t.Fatal("sequential Serve inherited a binding")
	}
	if got := sshMCPCall(t, client2, handle, bind); !bytes.Equal(got, []byte{sshAgentSuccess}) {
		t.Fatal("fresh epoch did not accept a fresh binding")
	}
}

func TestMCPSSHResponseAndStateBounds(t *testing.T) {
	env := newSSHEnv(t)
	for _, valid := range [][]byte{{sshAgentFailure}, {sshAgentSuccess}, {sshAgentExtensionFailure}, sshEmptyIdentities(), sshIdentities(env.userBlob), sshSignResponse(marshalEd25519Sig(make([]byte, 64)))} {
		if !validCapSSHResponse(valid) {
			t.Fatal("closed response rejected")
		}
		if validCapSSHResponse(append(dup(valid), 0)) {
			t.Fatal("trailing SSH response accepted")
		}
	}
	for _, invalid := range [][]byte{nil, {sshAgentRequestIdentities}, bytes.Repeat([]byte{1}, 89), {sshAgentIdentitiesAnswer, 0, 0, 0, 2}, sshIdentities([]byte{1})} {
		if validCapSSHResponse(invalid) {
			t.Fatal("open SSH response accepted")
		}
	}
	epoch := newCapSSHEpoch()
	defer epoch.close()
	for i := 0; i < maxAgentCapEntries; i++ {
		var h [32]byte
		h[0] = byte(i)
		epoch.retire(h)
	}
	if len(epoch.slots) != maxAgentCapEntries {
		t.Fatal("tombstones dropped")
	}
	var extra [32]byte
	extra[0] = 64
	epoch.retire(extra)
	if !epoch.closed || len(epoch.slots) != maxAgentCapEntries {
		t.Fatal("epoch did not fail closed at bound")
	}
	// Cancel before lazy creation is permanent for the epoch.
	fresh := newCapSSHEpoch()
	defer fresh.close()
	fresh.retire(extra)
	if _, ok := fresh.stream(extra, env.stream.broker, env.agent.ID, env.stream.bound); ok {
		t.Fatal("pre-dispatch cancellation recreated stream")
	}
	// Canonical base64 remains mandatory at the existing outer boundary.
	h := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, p := range []string{"Cw", "Cw==\n", "Cw== "} {
		raw, _ := json.Marshal(map[string]any{"handle": h, "payload": p})
		if _, _, err := toolInvokeArgs(raw); err == nil {
			t.Fatal("noncanonical SSH payload accepted")
		}
	}
}

func TestMCPSSHDiscoveryRestrictions(t *testing.T) {
	env := newSSHEnv(t)
	grant, _ := env.session.grantByID(env.grant.ID)
	if !env.session.capGrantSupported(grant) {
		t.Fatal("canonical exact SSH grant excluded")
	}
	for _, change := range []func(*grantRecord){
		func(g *grantRecord) { g.CredentialClass = CredTypeEd25519 },
		func(g *grantRecord) { g.Operations = []string{OpSSHUserAuth, OpLocalArtifactAttest} },
		func(g *grantRecord) { g.SSHHostKey = append(dup(g.SSHHostKey), 0) },
		func(g *grantRecord) { g.SSHUsername = "" },
		func(g *grantRecord) { g.KeyID = "" },
	} {
		candidate := grant
		change(&candidate)
		if env.session.capGrantSupported(candidate) {
			t.Fatal("noncanonical SSH grant discovered")
		}
	}
	shared := newSharedEnv(t)
	grant.AgentID = shared.agent.ID
	grant.CredentialID = shared.cred.ID
	if shared.s.capGrantSupported(grant) {
		t.Fatal("shared SSH authority added")
	}
}

func TestMCPSSHRetiredStreamWiping(t *testing.T) {
	env := newSSHEnv(t)
	for _, active := range []bool{false, true} {
		epoch := newCapSSHEpoch()
		var h [32]byte
		h[0] = 1
		stream, ok := epoch.stream(h, env.stream.broker, env.agent.ID, env.stream.bound)
		if !ok {
			t.Fatal("missing stream lease")
		}
		sid := env.sessionID(32)
		if resp, err := stream.roundTrip(env.bindBody(sid, env.hostBlob, env.hostSig(env.hostPriv, sid), 0)); err != nil || !bytes.Equal(resp, []byte{sshAgentSuccess}) {
			t.Fatal("bind")
		}
		if !active {
			epoch.release(h, stream)
		}
		idle := epoch.retire(h)
		if active && idle != nil {
			t.Fatal("active stream transferred before handler return")
		}
		if !active && idle != stream {
			t.Fatal("idle stream not detached")
		}
		idle.Close()
		if active {
			epoch.release(h, stream)
		}
		if !stream.closed || stream.hasBinding || stream.hostKey != nil || stream.sessionID != nil || stream.hostSig != nil {
			t.Fatal("retired stream retained binding buffers")
		}
		if len(epoch.slots) != 1 || !epoch.slots[h].retired || epoch.slots[h].stream != nil {
			t.Fatal("retirement lost bounded tombstone")
		}
		epoch.close()
	}
}
