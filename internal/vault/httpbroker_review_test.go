package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// Percent-encoders disagree about which bytes to escape, so an upstream that
// rebuilds a URL echoes a query-injected credential in a mixed spelling.
func TestRedactionReadsMixedPercentEncoding(t *testing.T) {
	secret := []byte("AbC+dEf/gHi=~x!")
	inj := grantInjection{style: InjectQuery, name: "api_key"}
	for name, echoed := range map[string]string{
		"python quote":             "AbC%2BdEf/gHi%3D~x%21",
		"java URLEncoder":          "AbC%2BdEf%2FgHi%3D%7Ex%21",
		"js encodeURIComponent":    "AbC%2BdEf%2FgHi%3D~x!",
		"lower-case hex":           "AbC%2bdEf%2fgHi%3d~x!",
		"every byte escaped":       "%41%62%43%2B%64%45%66%2F%67%48%69%3D%7E%78%21",
		"escaped twice":            "AbC%252BdEf%252FgHi%253D~x%2521",
		"raw, nothing escaped":     string(secret),
		"go QueryEscape, as today": url.QueryEscape(string(secret)),
	} {
		t.Run(name, func(t *testing.T) {
			upstream := http.Header{}
			upstream.Set("Link", `<https://svc.example/v1/issues?page=2&api_key=`+echoed+`>; rel="next"`)
			body := []byte(`{"next":"https://svc.example/v1/issues?page=2&api_key=` + echoed + `&z=1"}`)
			out, err := projectResponse(inj, secret, upstream, body, false)
			if err != nil {
				t.Fatalf("withheld, want redacted: %v", err)
			}
			want := `{"next":"https://svc.example/v1/issues?page=2&api_key=` + redacted + `&z=1"}`
			if string(out.Body) != want {
				t.Errorf("body = %s", out.Body)
			}
			if link := out.Headers["Link"]; !strings.Contains(link, "api_key="+redacted+">") {
				t.Errorf("Link = %s", link)
			}
		})
	}
}

func TestSpellsReadsEscapesAndCuts(t *testing.T) {
	for _, tc := range []struct {
		buf, form string
		n         int
		cut       bool
	}{
		{"a+b", "a+b", 3, false},
		{"a%2Bb tail", "a+b", 5, false},
		{"a%2bb", "a+b", 5, false},
		{"a%2Cb", "a+b", 0, false},
		// A literal percent sign in the credential, as written and escaped.
		{"50%25off", "50%off", 8, false},
		{"50%off", "50%off", 6, false},
		{"50%25", "50%25", 5, false},
		{"50%2525", "50%25", 7, false},
		{"%", "%", 1, false},
		// A space, as form encoding and as each escape case writes it.
		{"a+b%2fc", "a b/c", 7, false},
		{"a%20b%2Fc", "a b/c", 9, false},
		{"a b/c", "a b/c", 5, false},
		{"a+b", "a+b", 3, false},
		{"a b", "a+b", 0, false},
		{"%25", "%", 3, false},
		// buf ends partway through a spelling.
		{"a%2B", "a+b", 0, true},
		{"a%2", "a+b", 0, true},
		{"a%", "a+b", 0, true},
		{"a", "a+b", 0, true},
		{"a%3", "a+b", 0, false},
		{"50%25", "50%off", 0, true},
		{"", "a+b", 0, false},
		{"x", "a+b", 0, false},
	} {
		n, cut := spells([]byte(tc.buf), []byte(tc.form), false)
		if n != tc.n || cut != tc.cut {
			t.Errorf("spells(%q, %q) = %d, %v; want %d, %v", tc.buf, tc.form, n, cut, tc.n, tc.cut)
		}
	}
	if n, _ := spells([]byte("DEADbeef"), []byte("deadBEEF"), true); n != 8 {
		t.Errorf("hex spelling did not match across letter case: %d", n)
	}
}

// A body cut at the cap must not end in the start of a mixed spelling.
func TestTruncationDropsPartialMixedSpelling(t *testing.T) {
	secret := []byte("AbC+dEf/gHi=")
	forms := credentialForms(grantInjection{style: InjectQuery, name: "k"}, secret)
	for _, tail := range []string{"A", "AbC%2BdEf/g", "AbC%2", "AbC%", "%41%62"} {
		got := redactForms([]byte("k="+tail), forms, true)
		if string(got) != "k=" {
			t.Errorf("tail %q survived truncation as %q", tail, got)
		}
	}
	if got := redactForms([]byte("k=AbC%2BdEf/g"), forms, false); string(got) != "k=AbC%2BdEf/g" {
		t.Errorf("a whole body lost bytes that are not a credential: %q", got)
	}
}

// The credential inside the base64 of something longer reads differently at
// each byte alignment, and none of them is the base64 of the credential alone.
func TestShiftedBase64EchoIsWithheld(t *testing.T) {
	secret := []byte("ghp_" + strings.Repeat("Z", 30) + "+/?~>>")
	inj := grantInjection{style: InjectBearer}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		for _, lead := range []string{"", "x", "xy", "Authorization: Bearer "} {
			for _, trail := range []string{"", "\n", "\r\n", ":x-oauth-basic"} {
				echo := enc.EncodeToString([]byte(lead + string(secret) + trail))
				out, err := projectResponse(inj, secret, http.Header{}, []byte(`{"raw":"`+echo+`"}`), false)
				if err == nil && bytes.Contains(out.Body, []byte(echo[4:len(echo)-4])) {
					t.Errorf("lead %q trail %q: projected %s", lead, trail, out.Body)
				}
				h := http.Header{}
				h.Set("ETag", echo)
				if out, err := projectResponse(inj, secret, h, nil, false); err == nil && strings.Contains(out.Headers["Etag"], echo[4:len(echo)-4]) {
					t.Errorf("lead %q trail %q: projected header %s", lead, trail, out.Headers["Etag"])
				}
			}
		}
	}
	// A body cut inside the echo keeps none of the run.
	echo := base64.StdEncoding.EncodeToString([]byte("Authorization: Bearer " + string(secret)))
	lead := base64.StdEncoding.EncodeToString([]byte("Authorization: Bearer "))[:28]
	for cut := len(lead) + 1; cut < len(echo); cut++ {
		out, err := projectResponse(inj, secret, http.Header{}, []byte(echo[:cut]), true)
		if err == nil && len(out.Body) > len(lead)+2 {
			t.Fatalf("cut at %d kept %q", cut, out.Body[len(lead):])
		}
	}
}

func TestOrdinaryBase64IsNotWithheld(t *testing.T) {
	secret := []byte("ghp_" + strings.Repeat("Z", 36))
	body := []byte(`{"content":"` + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("package main\n", 40))) + `"}`)
	out, err := projectResponse(grantInjection{style: InjectBearer}, secret, http.Header{}, body, false)
	if err != nil || !bytes.Equal(out.Body, body) {
		t.Fatalf("err %v body %s", err, out.Body)
	}
	if forms := shiftedBase64([]byte("abcde")); len(forms) != 0 {
		t.Fatalf("a 5-byte credential produced shifted forms: %q", forms)
	}
}

// Every field name a framework reads as the real method is refused before the
// upstream is called, not only _method.
func TestMethodOverrideFieldNamesAreRefused(t *testing.T) {
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	json := map[string]string{"Content-Type": "application/json"}
	utf16le := func(s string) []byte {
		var b []byte
		for _, r := range utf16.Encode([]rune(s)) {
			b = append(b, byte(r), byte(r>>8))
		}
		return b
	}
	cases := map[string]HTTPRequest{
		"query X-HTTP-Method-Override": {Query: "X-HTTP-Method-Override=DELETE"},
		"query x-http-method-override": {Query: "a=1&x-http-method-override=DELETE"},
		"query X-HTTP-Method":          {Query: "X-HTTP-Method=DELETE"},
		"query X-Method-Override":      {Query: "X-Method-Override=DELETE"},
		"query _HttpMethod":            {Query: "_HttpMethod=DELETE"},
		"query _httpmethod":            {Query: "_httpmethod=DELETE"},
		"form X-HTTP-Method-Override":  {Headers: form, Body: []byte("X-HTTP-Method-Override=DELETE")},
		"form escaped _HttpMethod":     {Headers: form, Body: []byte("a=1&%5FHttpMethod=DELETE")},
		"json _HttpMethod":             {Headers: json, Body: []byte(`{"_HttpMethod":"DELETE"}`)},
		"utf-16 form _method": {
			Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=UTF-16LE"},
			Body:    append(append(utf16le("_method"), '='), utf16le("DELETE")...),
		},
		"utf-16 json": {
			Headers: map[string]string{"Content-Type": "application/json; charset=utf-16"},
			Body:    utf16le(`{"a":1}`),
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newHTTPBrokerEnv(t, InjectBearer, "", http.MethodPost)
			req := e.request(brokerTestPrefix + "/issues/1")
			req.Method, req.Query, req.Headers, req.Body = http.MethodPost, c.Query, c.Headers, c.Body
			if _, err := e.principal.BrokerRequest(req); !errors.Is(err, ErrDeniedMalformed) {
				t.Fatalf("err = %v, want denied_malformed", err)
			}
			if e.requests != 0 || e.lastResult(t) != resultDeniedMalformed {
				t.Fatalf("requests %d, audit %q", e.requests, e.lastResult(t))
			}
		})
	}
	for name, c := range map[string]HTTPRequest{
		"utf-8 form":       {Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}, Body: []byte("title=x&method=DELETE")},
		"json method word": {Headers: json, Body: []byte(`{"http_method":"DELETE","note":"_HttpMethod"}`)},
	} {
		t.Run("allowed "+name, func(t *testing.T) {
			e := newHTTPBrokerEnv(t, InjectBearer, "", http.MethodPost)
			req := e.request(brokerTestPrefix + "/issues/1")
			req.Method, req.Headers, req.Body = http.MethodPost, c.Headers, c.Body
			if _, err := e.principal.BrokerRequest(req); err != nil || e.requests != 1 {
				t.Fatalf("err %v, requests %d", err, e.requests)
			}
		})
	}
}

// An upstream that sends its headers and then holds the body must stall only
// the agent that called it. The owner and every other agent share one session.
func TestSlowUpstreamBodyDoesNotHoldTheSession(t *testing.T) {
	for name, withBody := range map[string]bool{"status only": false, "captured body": true} {
		t.Run(name, func(t *testing.T) {
			e := newHTTPBrokerEnv(t, InjectBearer, "")
			target := brokerTestOrigin + brokerTestPrefix + "/status"
			if _, err := e.s.IssueGrant(GrantSpec{
				AgentID: e.agentID, CredentialID: e.credID, Operations: []string{OpHTTPRequest},
				Resource: http.MethodGet + " " + target, ExpiresAt: time.Now().UTC().Add(time.Hour),
			}); err != nil {
				t.Fatal(err)
			}
			sent, release := make(chan struct{}), make(chan struct{})
			e.handler = func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				close(sent)
				<-release
				_, _ = w.Write([]byte("done"))
			}
			brokered := make(chan error, 1)
			go func() {
				var err error
				if withBody {
					_, err = e.principal.BrokerRequest(e.request(brokerTestPrefix))
				} else {
					_, err = e.principal.BrokerHTTP(HTTPBrokerRequest{CredentialID: e.credID, Method: http.MethodGet, Target: target})
				}
				brokered <- err
			}()
			<-sent
			// Give the broker time to move from the headers to the body read.
			time.Sleep(200 * time.Millisecond)
			listed := make(chan error, 1)
			go func() { _, err := e.s.List(); listed <- err }()
			select {
			case err := <-listed:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(5 * time.Second):
				t.Error("the owner's List waited on an agent's upstream body")
			}
			close(release)
			if err := <-brokered; err != nil {
				t.Errorf("broker: %v", err)
			}
		})
	}
}

// An alert names an agent. It must not name one for what the upstream or the
// resolver did: a redirect that stays on the granted origin (GitHub answers a
// renamed repository that way), a 304, or a granted name the resolver points
// at a private address. A redirect to another origin still alerts.
func TestUpstreamAndResolverFaultsDoNotAlert(t *testing.T) {
	for name, tc := range map[string]struct {
		handler http.HandlerFunc
		resolve []net.IP
		want    string
		err     error
		alerts  int
	}{
		"same-origin redirect": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", brokerTestPrefix+"/moved")
				w.WriteHeader(http.StatusMovedPermanently)
			},
			want: resultUpstreamError, err: ErrBrokerUpstream,
		},
		"not modified": {
			handler: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotModified) },
			want:    resultUpstreamError, err: ErrBrokerUpstream,
		},
		"redirect to another origin": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "https://attacker.example/collect")
				w.WriteHeader(http.StatusFound)
			},
			want: resultDeniedRedirect, err: ErrDeniedRedirect, alerts: 1,
		},
		"resolver answers with a private address": {
			resolve: []net.IP{net.ParseIP("10.0.0.7")},
			want:    resultDeniedDestination, err: ErrDeniedDestination,
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newHTTPBrokerEnv(t, InjectBearer, "")
			note := &MemoryNotifier{}
			if err := e.s.SetNotifier(note); err != nil {
				t.Fatal(err)
			}
			// The strictest containment: nothing here may trip it.
			if err := e.s.SetResponsePolicy(ResponsePolicy{High: ContainSuspendAgent}); err != nil {
				t.Fatal(err)
			}
			if tc.handler != nil {
				e.handler = tc.handler
			}
			if tc.resolve != nil {
				e.s.resolve = func(context.Context, string) ([]net.IP, error) { return tc.resolve, nil }
			}
			if _, err := e.principal.BrokerRequest(e.request(brokerTestPrefix)); !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			if got := e.lastResult(t); got != tc.want {
				t.Fatalf("audit result %q, want %q", got, tc.want)
			}
			if got := len(note.Snapshot()); got != tc.alerts {
				t.Fatalf("%d alerts, want %d: %+v", got, tc.alerts, note.Snapshot())
			}
			if active := e.s.agentActive(e.agentID); active != (tc.alerts == 0) {
				t.Fatalf("agent active = %v", active)
			}
		})
	}
}

// The MCP result carries a broker body twice, once inside a JSON string, so
// markup and quotes grow it several times over. A body under the 32 KiB cap
// that would outgrow the frame is cut and marked truncated. It used to become
// "internal error" after the upstream call had already run.
func TestBrokerBodyIsCutToFitTheMCPFrame(t *testing.T) {
	secret := []byte("ghp_" + strings.Repeat("Z", 36))
	inj := grantInjection{style: InjectBearer}
	for name, body := range map[string][]byte{
		"ascii":   bytes.Repeat([]byte("a"), maxAgentBody),
		"quotes":  bytes.Repeat([]byte(`"`), maxAgentBody),
		"markup":  bytes.Repeat([]byte("<"), maxAgentBody),
		"html":    bytes.Repeat([]byte("<b>text</b>"), maxAgentBody/11),
		"json":    bytes.Repeat([]byte(`{"k":"v"},`), maxAgentBody/10),
		"control": bytes.Repeat([]byte("\x01"), maxAgentBody),
		"rune":    bytes.Repeat([]byte(" "), maxAgentBody/3),
	} {
		t.Run(name, func(t *testing.T) {
			out, err := projectResponse(inj, secret, http.Header{"Content-Type": []string{"text/html"}}, body, false)
			if err != nil {
				t.Fatalf("withheld: %v", err)
			}
			res, err := toolValue(brokerBody(out))
			if err != nil {
				t.Fatalf("tool result refused: %v", err)
			}
			raw, err := json.Marshal(res)
			if err != nil {
				t.Fatal(err)
			}
			id, _ := jsonrpc.MakeID(float64(7))
			frame := frameFor(&jsonrpc.Response{ID: id, Result: raw})
			if len(frame) > maxMCPFrame || bytes.Contains(frame, []byte(`"error"`)) {
				t.Fatalf("frame of %d bytes: %.80s", len(frame), frame)
			}
			if !utf8.Valid(out.Body) || !bytes.HasPrefix(body, out.Body) {
				t.Fatal("the cut body is not a clean prefix of the upstream body")
			}
			if cut := len(out.Body) < len(body); cut != out.Truncated {
				t.Fatalf("kept %d of %d bytes, truncated=%v", len(out.Body), len(body), out.Truncated)
			}
			if name == "ascii" && out.Truncated {
				t.Fatal("a plain 32 KiB body was cut")
			}
			if len(out.Body) < maxAgentBody/8 {
				t.Fatalf("only %d bytes kept", len(out.Body))
			}
		})
	}
}
