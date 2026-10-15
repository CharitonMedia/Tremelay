package vault

import (
	"errors"
	"log"
	"testing"
	"time"
)

func TestGrantCreateBrokerResourcePolicy(t *testing.T) {
	path, pass, s := mustCreate(t, log.Default())
	defer wipe(pass)
	cred, err := s.Put("api", "api_key", []byte("test-secret-value"), PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := s.CreateAgent("worker")
	if err != nil {
		t.Fatal(err)
	}
	base := GrantSpec{
		AgentID:      agent.ID,
		CredentialID: cred.ID,
		Operations:   []string{OpHTTPBroker},
		Resource:     brokerTestOrigin + brokerTestPrefix,
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		HTTPMethods:  []string{"GET"},
		HTTPInject:   InjectBearer,
	}
	cases := []struct {
		resource string
		msg      string
		reason   string
	}{
		{
			resource: "http://127.0.0.1:18977/echo",
			msg:      "resource must use https",
			reason:   ReasonResourceHTTPS,
		},
		{
			resource: "https://127.0.0.1:18977/echo",
			msg:      "resource host must be a public DNS name, not an IP address",
			reason:   ReasonResourcePublicHost,
		},
		{
			resource: "https://localhost/v1",
			msg:      "resource host is loopback/private",
			reason:   ReasonResourcePrivateHost,
		},
	}
	for _, tc := range cases {
		spec := base
		spec.Resource = tc.resource
		_, err := s.IssueGrant(spec)
		if err == nil || err.Error() != tc.msg || !errors.Is(err, ErrInvalid) {
			t.Fatalf("%q: got %v want %q", tc.resource, err, tc.msg)
		}
		row := s.audit[len(s.audit)-1]
		if row.Action != actionGrantCreate || row.Result != resultDenied || row.Reasons != tc.reason || row.V != auditGrantDenialVersion {
			t.Fatalf("%q audit %+v", tc.resource, row)
		}
	}
	if _, err := s.IssueGrant(base); err != nil {
		t.Fatalf("valid resource refused: %v", err)
	}
	allowed := s.audit[len(s.audit)-1]
	if allowed.Result != resultAllowed || allowed.V != auditCapabilityVersion || allowed.Reasons != "" {
		t.Fatalf("allowed grant audit %+v", allowed)
	}
	_ = path
}
