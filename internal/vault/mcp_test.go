package vault

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPBounds(t *testing.T) {
	if base64.StdEncoding.EncodedLen(MaxAttestPayload) != 87384 {
		t.Fatalf("payload base64 %d", base64.StdEncoding.EncodedLen(MaxAttestPayload))
	}
	if base64.StdEncoding.EncodedLen(32) != 44 {
		t.Fatal("handle base64")
	}
	ceil := mcpMaxInvokeFrame()
	if ceil >= maxMCPFrame || ceil <= base64.StdEncoding.EncodedLen(MaxAttestPayload) {
		t.Fatalf("invoke ceiling %d cap %d", ceil, maxMCPFrame)
	}
}

func TestMCPJSON(t *testing.T) {
	if _, err := parseJSONValue([]byte(`{"a":1,"\u0061":2}`)); err == nil {
		t.Fatal("escaped duplicate was accepted")
	}
	if _, err := parseJSONValue([]byte(`{"a":1}{"b":2}`)); err == nil {
		t.Fatal("trailing value was accepted")
	}
	if _, err := parseJSONValue([]byte(`[1,2]`)); err == nil {
		t.Fatal("batch was accepted")
	}
	if _, err := parseJSONValue([]byte{0xff}); err == nil {
		t.Fatal("invalid utf-8 was accepted")
	}
	if _, err := parseJSONValue([]byte(`{"n":1.5}`)); err == nil {
		t.Fatal("fraction was accepted")
	}
	v, err := parseJSONValue([]byte(" \t{\"ok\":true}\r\n"))
	if err != nil || !v.has("ok") {
		t.Fatal(err)
	}
}

func TestMCPOutputGuard(t *testing.T) {
	id, err := jsonrpc.MakeID(float64(7))
	if err != nil {
		t.Fatal(err)
	}
	sentinel := strings.Repeat("SIG", 40)
	big, err := json.Marshal(strings.Repeat(sentinel, 4000))
	if err != nil || len(big) <= maxMCPFrame {
		t.Fatalf("fixture %d %v", len(big), err)
	}
	got := frameFor(&jsonrpc.Response{ID: id, Result: big})
	if bytes.Contains(got, []byte("SIG")) || !bytes.Contains(got, []byte(`"message":"internal error"`)) {
		t.Fatalf("oversized result leaked: %s", got)
	}
	if len(got) > maxMCPFrame+1 || !bytes.HasSuffix(got, []byte("\n")) {
		t.Fatalf("frame %d", len(got))
	}
	small, _ := json.Marshal(map[string]string{"signature": "ok-sig"})
	kept := frameFor(&jsonrpc.Response{ID: id, Result: small})
	if !bytes.Contains(kept, []byte("ok-sig")) {
		t.Fatalf("success stripped: %s", kept)
	}
	leak := &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "bad " + sentinel, Data: json.RawMessage(`{"v":"` + sentinel + `"}`)}
	scrubbed := frameFor(&jsonrpc.Response{ID: id, Error: leak})
	if bytes.Contains(scrubbed, []byte(sentinel)) || !bytes.Contains(scrubbed, []byte(`"message":"invalid params"`)) || bytes.Contains(scrubbed, []byte(`"data"`)) {
		t.Fatalf("error leaked: %s", scrubbed)
	}
}

func TestMCPSyntheticDemo(t *testing.T) {
	var logs bytes.Buffer
	env := newSharedEnvLog(t, &logs)
	spec := env.requestSpec(time.Hour, 30*time.Minute)
	req, err := env.bob.RequestAccess(spec)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := env.alice.Approve(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	beforeReq, beforeGrant := len(env.s.requests), len(env.s.grants)
	sess := startMCP(t, bindCap(t, env.s, env.agent.ID))
	if sess.cs.InitializeResult() == nil || sess.cs.InitializeResult().ProtocolVersion != mcpProtocolRevision {
		t.Fatalf("negotiated %+v", sess.cs.InitializeResult())
	}
	caps := sess.cs.InitializeResult().Capabilities
	if caps == nil || caps.Tools == nil || caps.Tools.ListChanged || caps.Logging != nil || caps.Prompts != nil || caps.Resources != nil || caps.Completions != nil {
		t.Fatalf("capabilities %+v", caps)
	}
	listed, err := sess.cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	rawTools, _ := json.Marshal(listed.Tools)
	if bytes.Contains(rawTools, []byte(spec.Resource)) || bytes.Contains(rawTools, []byte(toolRequest)) || bytes.Contains(rawTools, []byte(env.label)) {
		t.Fatal("tool list exposed a grant or request_capability")
	}
	for _, tool := range listed.Tools {
		names[tool.Name] = true
		var schema map[string]any
		encoded, _ := json.Marshal(tool.InputSchema)
		if err := json.Unmarshal(encoded, &schema); err != nil || schema["type"] != "object" || schema["additionalProperties"] != false {
			t.Fatalf("schema %s %s", tool.Name, encoded)
		}
	}
	if len(names) != 3 || !names[toolList] || !names[toolDescribe] || !names[toolInvoke] {
		t.Fatalf("tools %v", names)
	}
	cat := toolObject(t, mustCall(t, sess, toolList, map[string]any{}))
	entries, _ := cat["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("catalog %+v", cat)
	}
	entry := entries[0].(map[string]any)
	if entry["operation"] != OpLocalArtifactAttest || entry["resource"] != spec.Resource || entry["key_id"] != grant.KeyID || entry["status"] != GrantActive {
		t.Fatalf("entry %+v", entry)
	}
	handle, _ := entry["handle"].(string)
	described := toolObject(t, mustCall(t, sess, toolDescribe, map[string]any{"handle": handle}))
	if described["handle"] != handle || described["resource"] != spec.Resource || described["status"] != GrantActive {
		t.Fatalf("describe %+v", described)
	}
	payload := []byte("demo-artifact")
	invoked := toolObject(t, mustCall(t, sess, toolInvoke, map[string]any{
		"handle":  handle,
		"payload": base64.StdEncoding.EncodeToString(payload),
	}))
	sig := mustB64(t, invoked["signature"].(string))
	pub := mustB64(t, invoked["public_key"].(string))
	if invoked["domain"] != AttestDomain || invoked["purpose"] != AttestPurpose || invoked["resource"] != spec.Resource {
		t.Fatalf("projection %+v", invoked)
	}
	if !VerifyLocalAttestation(pub, spec.Resource, payload, sig) {
		t.Fatal("signature did not verify")
	}
	if _, err := sess.cs.CallTool(t.Context(), &mcp.CallToolParams{Name: toolRequest, Arguments: map[string]any{}}); err == nil || strings.Contains(err.Error(), toolRequest) {
		t.Fatalf("request_capability %v", err)
	}
	if len(env.s.requests) != beforeReq || len(env.s.grants) != beforeGrant {
		t.Fatal("request_capability created authority")
	}
	rawInv, _ := json.Marshal(invoked)
	assertNoCapLeak(t, rawInv, env, grant, payload)
	assertNoSecrets(t, []byte(sess.ep.logs.text()+sess.clientLog.text()+logs.String()), [][]byte{payload, env.der, []byte(env.sentinel)})
	for _, line := range strings.Split(sess.ep.logs.text()+sess.clientLog.text(), "\n") {
		if line != "" && line != "mcp" {
			t.Fatalf("log line %q", line)
		}
	}
	sawList, sawDescribe, sawAllowed, sawCompleted := false, false, false, false
	for _, ev := range env.s.audit {
		switch {
		case ev.Action == actionCapList && ev.Result == resultAllowed && ev.AgentID == env.agent.ID && ev.GrantID == "":
			sawList = true
		case ev.Action == actionAgentCap && ev.Result == resultAllowed && ev.GrantID == grant.ID:
			sawDescribe = true
		case ev.Action == actionLocalAttest && ev.Result == resultAllowed && ev.GrantID == grant.ID:
			sawAllowed = true
		case ev.Action == actionLocalAttest && ev.Result == resultCompleted && ev.GrantID == grant.ID:
			sawCompleted = true
		}
	}
	if !sawList || !sawDescribe || !sawAllowed || !sawCompleted {
		t.Fatalf("audit list=%v describe=%v allowed=%v completed=%v", sawList, sawDescribe, sawAllowed, sawCompleted)
	}
	if _, err := VerifyAudit(env.path, env.pass); err != nil {
		t.Fatal(err)
	}
}

func TestMCPWireAdmission(t *testing.T) {
	env := approvedShared(t)
	cap := bindCap(t, env.s, env.agent.ID)
	raw := startRaw(t, cap)
	list := rpcFrame(t, 1, "tools/list", map[string]any{"_meta": mcpMeta()})
	body := raw.round(t, list)
	if !bytes.Contains(body, []byte(toolInvoke)) || bytes.Contains(body, []byte(toolRequest)) {
		t.Fatalf("tools/list %s", body)
	}
	cat := rpcFrame(t, 2, "tools/call", map[string]any{
		"name": toolList, "arguments": map[string]any{}, "_meta": mcpMeta(),
	})
	listed := raw.round(t, cat)
	handle := handleFromList(t, listed)
	payload := []byte("wire-artifact")

	legacy := []byte(`{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}`)
	got := raw.round(t, legacy)
	if bytes.Contains(got, []byte("2025-11-25")) || bytes.Contains(got, []byte("protocolVersion")) || !bytes.Contains(got, []byte("unsupported protocol version")) {
		t.Fatalf("legacy initialize %s", got)
	}
	missing := rpcFrame(t, 4, "tools/call", map[string]any{"name": toolInvoke, "arguments": map[string]any{}})
	if got = raw.round(t, missing); !bytes.Contains(got, []byte("unsupported protocol version")) {
		t.Fatalf("missing revision %s", got)
	}
	badRev := rpcFrame(t, 5, "tools/call", map[string]any{
		"name": toolInvoke, "arguments": map[string]any{},
		"_meta": map[string]any{metaProtocolVersion: "2025-11-25", metaClientCapabilities: map[string]any{}, metaClientInfo: map[string]string{"name": "n", "version": "1"}},
	})
	before := len(env.s.audit)
	got = raw.round(t, badRev)
	if !bytes.Contains(got, []byte("unsupported protocol version")) || bytes.Contains(got, []byte("2025-11-25")) {
		t.Fatalf("mismatched revision %s", got)
	}
	if env.s.audit[len(env.s.audit)-1].Action != actionLocalAttest || len(env.s.audit) != before+1 {
		t.Fatal("mismatched invoke was not a sparse local_attest denial")
	}

	sentinel := "dup-sentinel-" + strings.Repeat("Q", 24)
	dup := []byte(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"invoke_capability","arguments":{"handle":"` + handle + `","\u0068andle":"` + sentinel + `"},"_meta":` + string(mustJSON(t, mcpMeta())) + `}}`)
	got = raw.round(t, dup)
	if bytes.Contains(got, []byte(sentinel)) || !bytes.Contains(got, []byte("parse error")) {
		t.Fatalf("duplicate %s", got)
	}
	unknown := rpcFrame(t, 7, "tools/call", map[string]any{
		"name": toolInvoke, "_meta": mcpMeta(),
		"arguments": map[string]any{"handle": handle, "payload": base64.StdEncoding.EncodeToString(payload), "extra": sentinel},
	})
	before = len(env.s.audit)
	got = raw.round(t, unknown)
	if bytes.Contains(got, []byte(sentinel)) || !bytes.Contains(got, []byte("invalid params")) {
		t.Fatalf("unknown field %s", got)
	}
	ev := env.s.audit[len(env.s.audit)-1]
	if ev.Action != actionLocalAttest || ev.Result != resultDenied || ev.GrantID != "" || len(env.s.audit) != before+1 {
		t.Fatalf("unknown-field audit %+v", ev)
	}
	badB64 := rpcFrame(t, 8, "tools/call", map[string]any{
		"name": toolInvoke, "_meta": mcpMeta(),
		"arguments": map[string]any{"handle": handle, "payload": "!!!!"},
	})
	if got = raw.round(t, badB64); bytes.Contains(got, []byte("!!!!")) || !bytes.Contains(got, []byte("invalid params")) {
		t.Fatalf("base64 %s", got)
	}
	nullHandle := rpcFrame(t, 9, "tools/call", map[string]any{
		"name": toolDescribe, "_meta": mcpMeta(), "arguments": map[string]any{"handle": nil},
	})
	if got = raw.round(t, nullHandle); !bytes.Contains(got, []byte("invalid params")) {
		t.Fatalf("null %s", got)
	}
	if got = raw.round(t, []byte("[{}]\n")); !bytes.Contains(got, []byte("parse error")) {
		t.Fatalf("batch %s", got)
	}
	if got = raw.round(t, []byte{0xff, '\n'}); bytes.Contains(got, []byte{0xff}) || !bytes.Contains(got, []byte("parse error")) {
		t.Fatalf("utf8 %s", got)
	}
	other := rpcFrame(t, 10, "resources/list", map[string]any{"_meta": mcpMeta()})
	if got = raw.round(t, other); !bytes.Contains(got, []byte("method not found")) || bytes.Contains(got, []byte("resources/list")) {
		t.Fatalf("method %s", got)
	}
	ask := rpcFrame(t, 11, "tools/call", map[string]any{
		"name": toolRequest, "arguments": map[string]any{}, "_meta": mcpMeta(),
	})
	nReq, nGrant := len(env.s.requests), len(env.s.grants)
	before = len(env.s.audit)
	got = raw.round(t, ask)
	if !bytes.Contains(got, []byte("invalid params")) || bytes.Contains(got, []byte(toolRequest)) {
		t.Fatalf("request_capability %s", got)
	}
	if len(env.s.requests) != nReq || len(env.s.grants) != nGrant || env.s.audit[len(env.s.audit)-1].Action != actionAgentCap || len(env.s.audit) != before+1 {
		t.Fatal("request_capability mutated authority or skipped the denial")
	}

	env.s.commitFault = func() error { return errors.New("induced " + sentinel) }
	before = len(env.s.audit)
	got = raw.round(t, ask)
	env.s.commitFault = nil
	if bytes.Contains(got, []byte(sentinel)) || bytes.Contains(got, []byte("persist")) || bytes.Contains(got, []byte("recorded")) || !bytes.Contains(got, []byte("internal error")) || len(env.s.audit) != before {
		t.Fatalf("audit fault %s rows %d", got, len(env.s.audit)-before)
	}

	blocked := make(chan struct{})
	release := make(chan struct{})
	env.s.attestFault = func() error {
		select {
		case <-blocked:
		default:
			close(blocked)
		}
		<-release
		return nil
	}
	inv := rpcFrame(t, 12, "tools/call", map[string]any{
		"name": toolInvoke, "_meta": mcpMeta(),
		"arguments": map[string]any{"handle": handle, "payload": base64.StdEncoding.EncodeToString(payload)},
	})
	if _, err := raw.w.Write(append(inv, '\n')); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not reach the callback")
	}
	second := rpcFrame(t, 13, "tools/call", map[string]any{
		"name": toolList, "arguments": map[string]any{}, "_meta": mcpMeta(),
	})
	cancel := []byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":12,"reason":"` + sentinel + `"}}`)
	if _, err := raw.w.Write(append(cancel, '\n')); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.w.Write(append(second, '\n')); err != nil {
		t.Fatal(err)
	}
	busy := raw.read(t)
	if !bytes.Contains(busy, []byte(`"id":13`)) || !bytes.Contains(busy, []byte("endpoint busy")) || bytes.Contains(busy, []byte(sentinel)) {
		t.Fatalf("busy %s", busy)
	}
	close(release)
	env.s.attestFault = nil
	ok := raw.read(t)
	if bytes.Contains(ok, []byte(sentinel)) || bytes.Contains(ok, []byte(base64.StdEncoding.EncodeToString(payload))) {
		t.Fatalf("invoke echoed payload %s", ok)
	}
	sig := signatureFrom(t, ok)
	if !VerifyLocalAttestation(env.priv.Public().(ed25519.PublicKey), env.resource, payload, sig) {
		t.Fatal("cancelled call did not keep the released signature")
	}
	if !auditHasGrant(env.s, actionLocalAttest, resultCompleted, env.s.grants[len(env.s.grants)-1].ID) {
		t.Fatal("completion missing")
	}
	if _, err := raw.w.Write(append(cancel, '\n')); err != nil {
		t.Fatal(err)
	}
	again := raw.round(t, rpcFrame(t, 14, "tools/list", map[string]any{"_meta": mcpMeta()}))
	if bytes.Contains(again, []byte(sentinel)) {
		t.Fatalf("late cancel %s", again)
	}
	if !VerifyLocalAttestation(env.priv.Public().(ed25519.PublicKey), env.resource, payload, sig) {
		t.Fatal("late cancel recalled the signature")
	}

	over := bytes.Repeat([]byte{'A'}, maxMCPFrame+8)
	_, _ = raw.w.Write(over)
	select {
	case <-raw.done:
	case <-time.After(5 * time.Second):
		t.Fatal("oversized frame did not close the endpoint")
	}
}

func TestMCPCallbackSerialization(t *testing.T) {
	env := newSharedEnv(t)
	first := approveExact(t, env, env.agent.ID, env.resource)
	second := approveExact(t, env, env.agent.ID, env.resource)
	bound := bindCap(t, env.s, env.agent.ID)
	sess := startMCP(t, bound)
	if n := len(entriesOf(t, mustCall(t, sess, toolList, map[string]any{}))); n != 2 {
		t.Fatalf("entries %d", n)
	}
	oldH, keepH := handlesFor(t, bound, first.ID, second.ID)
	oldHandle := base64.StdEncoding.EncodeToString(oldH[:])
	keepHandle := base64.StdEncoding.EncodeToString(keepH[:])
	env.s.attestFault = func() error {
		if err := sess.ep.denyOverlap(true); err != nil {
			t.Errorf("overlap %v", err)
		}
		return env.alice.RevokeGrant(second.ID)
	}
	res, err := sess.cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: toolInvoke,
		Arguments: map[string]any{
			"handle":  keepHandle,
			"payload": base64.StdEncoding.EncodeToString([]byte("during-callback")),
		},
	})
	env.s.attestFault = nil
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || toolObject(t, res)["code"] != capDeniedRevoked {
		t.Fatalf("callback retarget %+v", toolObject(t, res))
	}
	if auditHasGrant(env.s, actionLocalAttest, resultDeniedRevoked, first.ID) {
		t.Fatal("the other grant was blamed")
	}
	if !auditHasGrant(env.s, actionLocalAttest, resultDeniedRevoked, second.ID) {
		t.Fatal("selected grant was not denied")
	}
	kept := mustCall(t, sess, toolInvoke, map[string]any{
		"handle":  oldHandle,
		"payload": base64.StdEncoding.EncodeToString([]byte("other-grant")),
	})
	if kept.IsError {
		t.Fatalf("remaining grant %+v", toolObject(t, kept))
	}
	pub := mustB64(t, toolObject(t, kept)["public_key"].(string))
	sig := mustB64(t, toolObject(t, kept)["signature"].(string))
	if !VerifyLocalAttestation(pub, env.resource, []byte("other-grant"), sig) {
		t.Fatal("remaining grant did not verify")
	}
}

func TestMCPAuthority(t *testing.T) {
	t.Run("foreign", func(t *testing.T) {
		env := newSharedEnv(t)
		other, err := env.alice.CreateAgent("worker-2")
		if err != nil {
			t.Fatal(err)
		}
		approveExact(t, env, env.agent.ID, env.resource)
		approveExact(t, env, other.ID, "artifact-"+randHex(t, 8))
		a := startMCP(t, bindCap(t, env.s, env.agent.ID))
		b := startMCP(t, bindCap(t, env.s, other.ID))
		ah := entriesOf(t, mustCall(t, a, toolList, map[string]any{}))
		bh := entriesOf(t, mustCall(t, b, toolList, map[string]any{}))
		if len(ah) != 1 || len(bh) != 1 || ah[0]["resource"] == bh[0]["resource"] {
			t.Fatal("catalogs were not isolated")
		}
		denied := mustCall(t, a, toolInvoke, map[string]any{
			"handle": bh[0]["handle"], "payload": base64.StdEncoding.EncodeToString([]byte("foreign")),
		})
		if code := toolObject(t, denied)["code"]; code != capUnknownHandle {
			t.Fatalf("foreign %+v", toolObject(t, denied))
		}
		raw, _ := json.Marshal(toolObject(t, denied))
		if bytes.Contains(raw, []byte(bh[0]["resource"].(string))) {
			t.Fatal("foreign resource leaked")
		}
	})
	t.Run("revoked-expired-suspended", func(t *testing.T) {
		env := approvedShared(t)
		sess := startMCP(t, bindCap(t, env.s, env.agent.ID))
		handle := entriesOf(t, mustCall(t, sess, toolList, map[string]any{}))[0]["handle"]
		if err := env.alice.RevokeGrant(env.s.grants[len(env.s.grants)-1].ID); err != nil {
			t.Fatal(err)
		}
		if code := toolObject(t, mustCall(t, sess, toolInvoke, invokeArgs(handle, []byte("revoked"))))["code"]; code != capDeniedRevoked {
			t.Fatal(code)
		}
		exp := newSharedEnv(t)
		approveExact(t, exp, exp.agent.ID, exp.resource)
		expSess := startMCP(t, bindCap(t, exp.s, exp.agent.ID))
		expHandle := entriesOf(t, mustCall(t, expSess, toolList, map[string]any{}))[0]["handle"]
		exp.s.clock = func() time.Time { return time.Now().Add(2 * time.Hour) }
		if status := toolObject(t, mustCall(t, expSess, toolDescribe, map[string]any{"handle": expHandle}))["status"]; status != GrantExpired {
			t.Fatal(status)
		}
		if code := toolObject(t, mustCall(t, expSess, toolInvoke, invokeArgs(expHandle, []byte("expired"))))["code"]; code != capDeniedExpired {
			t.Fatal(code)
		}
		sus := approvedShared(t)
		susSess := startMCP(t, bindCap(t, sus.s, sus.agent.ID))
		susHandle := entriesOf(t, mustCall(t, susSess, toolList, map[string]any{}))[0]["handle"]
		for i := range sus.s.agents {
			if sus.s.agents[i].ID == sus.agent.ID {
				sus.s.agents[i].State = agentStateSuspended
			}
		}
		secret := []byte("suspended-" + sus.sentinel)
		res := mustCall(t, susSess, toolInvoke, invokeArgs(susHandle, secret))
		raw, _ := json.Marshal(toolObject(t, res))
		if toolObject(t, res)["code"] != capDeniedAgent || bytes.Contains(raw, secret) {
			t.Fatalf("suspended %s", raw)
		}
	})
	t.Run("membership-key-stale-locked", func(t *testing.T) {
		mem := approvedShared(t)
		memSess := startMCP(t, bindCap(t, mem.s, mem.agent.ID))
		memHandle := entriesOf(t, mustCall(t, memSess, toolList, map[string]any{}))[0]["handle"]
		if err := mem.alice.Remove(mem.bobID); err != nil {
			t.Fatal(err)
		}
		if code := toolObject(t, mustCall(t, memSess, toolInvoke, invokeArgs(memHandle, []byte("member"))))["code"]; code != capDeniedRevoked {
			t.Fatal(code)
		}

		fresh := newSharedEnv(t)
		old := approveExact(t, fresh, fresh.agent.ID, fresh.resource)
		_, priv2, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der2, err := x509.MarshalPKCS8PrivateKey(priv2)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fresh.alice.Replace(fresh.cred.ID, der2, LifecycleOptions{}); err != nil {
			t.Fatal(err)
		}
		next := approveExact(t, fresh, fresh.agent.ID, fresh.resource)
		bound := startMCP(t, bindCap(t, fresh.s, fresh.agent.ID))
		var oldHandle, newHandle string
		for _, entry := range entriesOf(t, mustCall(t, bound, toolList, map[string]any{})) {
			if entry["key_id"] == old.KeyID {
				oldHandle = entry["handle"].(string)
			}
			if entry["key_id"] == next.KeyID {
				newHandle = entry["handle"].(string)
			}
		}
		if toolObject(t, mustCall(t, bound, toolInvoke, invokeArgs(oldHandle, []byte("old-key"))))["code"] != capDeniedKey {
			t.Fatal("old key was accepted")
		}
		signed := toolObject(t, mustCall(t, bound, toolInvoke, invokeArgs(newHandle, []byte("new-key"))))
		pub := mustB64(t, signed["public_key"].(string))
		sig := mustB64(t, signed["signature"].(string))
		if !VerifyLocalAttestation(pub, fresh.resource, []byte("new-key"), sig) {
			t.Fatal("new handle did not verify")
		}
		if VerifyLocalAttestation(fresh.priv.Public().(ed25519.PublicKey), fresh.resource, []byte("new-key"), sig) {
			t.Fatal("new handle used the old key")
		}

		stale := approvedShared(t)
		staleSess := startMCP(t, bindCap(t, stale.s, stale.agent.ID))
		staleHandle := entriesOf(t, mustCall(t, staleSess, toolList, map[string]any{}))[0]["handle"]
		other, err := Unlock(stale.path, stale.pass, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(other.Lock)
		bob2, err := other.BindHuman(stale.bobID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bob2.RequestAccess(stale.requestSpec(time.Hour, 10*time.Minute)); err != nil {
			t.Fatal(err)
		}
		before := len(stale.s.audit)
		res, err := staleSess.cs.CallTool(t.Context(), &mcp.CallToolParams{Name: toolInvoke, Arguments: invokeArgs(staleHandle, []byte("stale-artifact"))})
		if err == nil || (res != nil && !res.IsError) || strings.Contains(err.Error(), "stale-artifact") || len(stale.s.audit) != before {
			t.Fatalf("stale %v %+v rows %d", err, res, len(stale.s.audit)-before)
		}

		locked := approvedShared(t)
		lockedSess := startMCP(t, bindCap(t, locked.s, locked.agent.ID))
		lockedHandle := entriesOf(t, mustCall(t, lockedSess, toolList, map[string]any{}))[0]["handle"]
		locked.s.Lock()
		res, err = lockedSess.cs.CallTool(t.Context(), &mcp.CallToolParams{Name: toolList, Arguments: map[string]any{}})
		if err == nil || strings.Contains(err.Error(), lockedHandle.(string)) {
			t.Fatalf("locked %v", err)
		}
	})
}

type mcpSession struct {
	ep        *MCPEndpoint
	cs        *mcp.ClientSession
	clientLog *mcpLog
	cancel    context.CancelFunc
}

func startMCP(t *testing.T, cap *AgentCapability) *mcpSession {
	t.Helper()
	ep, err := BindMCPEndpoint(cap)
	if err != nil {
		t.Fatal(err)
	}
	clientRead, serverWrite := io.Pipe()
	serverRead, clientWrite := io.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)
	go func() { errc <- ep.Serve(ctx, serverRead, serverWrite) }()
	t.Cleanup(func() {
		cancel()
		_ = clientWrite.Close()
		_ = clientRead.Close()
		select {
		case <-errc:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return")
		}
	})
	logs := &mcpLog{}
	client := mcp.NewClient(&mcp.Implementation{Name: "tremelay-local-mcp-client", Version: "m10b"}, &mcp.ClientOptions{
		Capabilities:   &mcp.ClientCapabilities{},
		Logger:         slog.New(logs),
		MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true},
	})
	cs, err := client.Connect(ctx, &mcp.IOTransport{
		Reader:        clientRead,
		Writer:        clientWrite,
		MaxLineLength: maxMCPFrame + 1,
	}, &mcp.ClientSessionOptions{ProtocolVersion: mcpProtocolRevision})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return &mcpSession{ep: ep, cs: cs, clientLog: logs, cancel: cancel}
}

type rawPipe struct {
	ep   *MCPEndpoint
	w    *io.PipeWriter
	r    *bufio.Reader
	done chan struct{}
}

func startRaw(t *testing.T, cap *AgentCapability) *rawPipe {
	t.Helper()
	ep, err := BindMCPEndpoint(cap)
	if err != nil {
		t.Fatal(err)
	}
	clientRead, serverWrite := io.Pipe()
	serverRead, clientWrite := io.Pipe()
	done := make(chan struct{})
	go func() {
		_ = ep.Serve(t.Context(), serverRead, serverWrite)
		close(done)
	}()
	t.Cleanup(func() {
		_ = clientWrite.Close()
		_ = clientRead.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
	return &rawPipe{ep: ep, w: clientWrite, r: bufio.NewReader(clientRead), done: done}
}

func (p *rawPipe) round(t *testing.T, frame []byte) []byte {
	t.Helper()
	if len(frame) == 0 || frame[len(frame)-1] != '\n' {
		frame = append(append([]byte{}, frame...), '\n')
	}
	if _, err := p.w.Write(frame); err != nil {
		t.Fatal(err)
	}
	return p.read(t)
}

func (p *rawPipe) read(t *testing.T) []byte {
	t.Helper()
	type got struct {
		b   []byte
		err error
	}
	ch := make(chan got, 1)
	go func() {
		var buf []byte
		for {
			b, err := p.r.ReadByte()
			if err != nil {
				ch <- got{buf, err}
				return
			}
			buf = append(buf, b)
			if b == '\n' || len(buf) > maxMCPFrame+1 {
				ch <- got{buf, nil}
				return
			}
		}
	}()
	select {
	case g := <-ch:
		if g.err != nil {
			t.Fatal(g.err)
		}
		return g.b
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a frame")
		return nil
	}
}

func mustCall(t *testing.T, sess *mcpSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := sess.cs.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func toolObject(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	if res == nil {
		t.Fatal("nil tool result")
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("%s %v", raw, err)
	}
	return m
}

func entriesOf(t *testing.T, res *mcp.CallToolResult) []map[string]any {
	t.Helper()
	raw, _ := json.Marshal(toolObject(t, res)["entries"])
	var out []map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func invokeArgs(handle any, payload []byte) map[string]any {
	return map[string]any{"handle": handle, "payload": base64.StdEncoding.EncodeToString(payload)}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

func mcpMeta() map[string]any {
	return map[string]any{
		metaProtocolVersion:    mcpProtocolRevision,
		metaClientInfo:         map[string]string{"name": "tremelay-local-mcp-client", "version": "m10b"},
		metaClientCapabilities: map[string]any{},
	}
}

func rpcFrame(t *testing.T, id int, method string, params any) []byte {
	t.Helper()
	return mustJSON(t, map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func handleFromList(t *testing.T, frame []byte) string {
	t.Helper()
	var resp struct {
		Result struct {
			Structured map[string]any `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(frame, &resp); err != nil {
		t.Fatal(err)
	}
	entries, _ := resp.Result.Structured["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("list %s", frame)
	}
	handle, _ := entries[0].(map[string]any)["handle"].(string)
	if handle == "" {
		t.Fatalf("handle %s", frame)
	}
	return handle
}

func signatureFrom(t *testing.T, frame []byte) []byte {
	t.Helper()
	var resp struct {
		Result struct {
			Structured map[string]string `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(frame, &resp); err != nil {
		t.Fatal(err)
	}
	return mustB64(t, resp.Result.Structured["signature"])
}
