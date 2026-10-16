package vault

import (
	"errors"
	"log"
	"strings"
	"testing"
	"time"
)

func TestGrantCreateInputDenials(t *testing.T) {
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
	scope := "scope-" + randHex(t, 16)
	exp := time.Now().UTC().Add(time.Hour)
	base := GrantSpec{
		AgentID:      agent.ID,
		CredentialID: cred.ID,
		Operations:   []string{OpHTTPRequest},
		Resource:     scope,
		ExpiresAt:    exp,
	}
	cases := []struct {
		spec   GrantSpec
		msg    string
		reason string
	}{
		{
			spec:   GrantSpec{CredentialID: cred.ID, Operations: []string{OpHTTPRequest}, Resource: scope, ExpiresAt: exp},
			msg:    "--agent is required",
			reason: ReasonAgentRequired,
		},
		{
			spec:   GrantSpec{AgentID: agent.ID, Operations: []string{OpHTTPRequest}, Resource: scope, ExpiresAt: exp},
			msg:    "--credential or --class is required",
			reason: ReasonCredentialRequired,
		},
		{
			spec:   GrantSpec{AgentID: agent.ID, CredentialID: cred.ID, CredentialClass: "api_key", Operations: []string{OpHTTPRequest}, Resource: scope, ExpiresAt: exp},
			msg:    "specify only one of --credential or --class",
			reason: ReasonCredentialConflict,
		},
		{
			spec:   GrantSpec{AgentID: agent.ID, CredentialID: cred.ID, Resource: scope, ExpiresAt: exp},
			msg:    "--operation is required",
			reason: ReasonOperationRequired,
		},
		{
			spec:   GrantSpec{AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{"get_secret"}, Resource: scope, ExpiresAt: exp},
			msg:    "unknown --operation; valid:",
			reason: ReasonUnknownOperation,
		},
		{
			spec:   GrantSpec{AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{OpHTTPRequest, OpHTTPRequest}, Resource: scope, ExpiresAt: exp},
			msg:    "duplicate operation",
			reason: ReasonDuplicateOperation,
		},
		{
			spec:   GrantSpec{AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{OpHTTPRequest}, ExpiresAt: exp},
			msg:    "--resource is required",
			reason: ReasonResourceRequired,
		},
		{
			spec:   GrantSpec{AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{OpHTTPRequest}, Resource: "svc*", ExpiresAt: exp},
			msg:    "--resource is invalid",
			reason: ReasonResourceInvalid,
		},
		{
			spec:   GrantSpec{AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{OpHTTPRequest}, Resource: scope, ExpiresAt: time.Time{}},
			msg:    "--expires is invalid",
			reason: ReasonExpiresInvalid,
		},
		{
			spec:   GrantSpec{AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{OpHTTPRequest}, Resource: scope, ExpiresAt: time.Now().UTC().Add(-time.Hour)},
			msg:    "--expires must be in the future",
			reason: ReasonExpiresNotFuture,
		},
		{
			spec:   GrantSpec{AgentID: agent.ID, CredentialClass: "not_a_type", Operations: []string{OpHTTPRequest}, Resource: scope, ExpiresAt: exp},
			msg:    "unknown --class; valid:",
			reason: ReasonUnknownClass,
		},
		{
			spec:   GrantSpec{AgentID: agent.ID, CredentialID: "not-a-valid-id", Operations: []string{OpHTTPRequest}, Resource: scope, ExpiresAt: exp},
			msg:    "--credential is invalid",
			reason: ReasonInvalidCredentialID,
		},
	}
	for _, tc := range cases {
		_, err := s.IssueGrant(tc.spec)
		if err == nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.msg) {
			t.Fatalf("spec %+v: got %v want substring %q", tc.spec, err, tc.msg)
		}
		row := s.audit[len(s.audit)-1]
		if row.Action != actionGrantCreate || row.Result != resultDenied || row.Reasons != tc.reason || row.V != auditGrantDenialVersion {
			t.Fatalf("%q audit %+v", tc.msg, row)
		}
	}
	if _, err := s.IssueGrant(base); err != nil {
		t.Fatalf("valid grant refused: %v", err)
	}
	allowed := s.audit[len(s.audit)-1]
	if allowed.Result != resultAllowed || allowed.Reasons != "" {
		t.Fatalf("allowed audit %+v", allowed)
	}
	_ = path
}

func TestRejectGrantCreateReason(t *testing.T) {
	_, pass, s := mustCreate(t, log.Default())
	defer wipe(pass)
	if err := s.RejectGrantCreate("", errGrantOperationRequired()); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	row := s.audit[len(s.audit)-1]
	if row.Reasons != ReasonOperationRequired || row.V != auditGrantDenialVersion {
		t.Fatalf("audit %+v", row)
	}
}
