package vault

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

// All state changes use the human control-plane
// API; only the trusted test clock changes for expiry. No live keys or network.
func TestLocalAttestRotationOrderReopenAndLifecycle(t *testing.T) {
	for _, currentHigher := range []bool{false, true} {
		name := "current_lower_id"
		if currentHigher {
			name = "current_higher_id"
		}
		for _, outcome := range []string{"active", "revoked", "expired"} {
			t.Run(name+"/"+outcome, func(t *testing.T) {
				path, pass, s := mustCreate(t, nil)
				defer func() { s.Lock() }()
				pubA, privA := mustEd25519(t)
				pubB, privB := mustEd25519(t)
				derA, err := x509.MarshalPKCS8PrivateKey(privA)
				if err != nil {
					t.Fatal(err)
				}
				derB, err := x509.MarshalPKCS8PrivateKey(privB)
				if err != nil {
					t.Fatal(err)
				}
				cred, err := s.Put("synthetic-key", CredTypeEd25519, derA, PutOptions{})
				if err != nil {
					t.Fatal(err)
				}
				agent, err := s.CreateAgent("review-worker")
				if err != nil {
					t.Fatal(err)
				}
				expires := time.Now().Add(time.Hour).UTC()
				spec := GrantSpec{AgentID: agent.ID, CredentialID: cred.ID, Operations: []string{OpLocalArtifactAttest}, Resource: "artifact:review", ExpiresAt: expires}
				grantA, err := s.IssueGrant(spec)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = s.Replace(cred.ID, derB, LifecycleOptions{}); err != nil {
					t.Fatal(err)
				}
				grantB, err := s.IssueGrant(spec)
				if err != nil {
					t.Fatal(err)
				}
				current, stale := grantB, grantA
				currentDER, staleDER := derB, derA
				currentPub, stalePub := ed25519.PublicKey(pubB), ed25519.PublicKey(pubA)
				if (grantB.ID > grantA.ID) != currentHigher {
					current, stale = grantA, grantB
					currentDER, staleDER = derA, derB
					currentPub, stalePub = pubA, pubB
					if _, err = s.Replace(cred.ID, currentDER, LifecycleOptions{}); err != nil {
						t.Fatal(err)
					}
				}
				req := LocalAttestRequest{CredentialID: cred.ID, Resource: spec.Resource, Payload: []byte("bounded synthetic artifact")}
				checkAllowed := func() {
					t.Helper()
					p, err := s.Agent(agent.ID)
					if err != nil {
						t.Fatal(err)
					}
					id, err := p.Authorize(cred.ID, OpLocalArtifactAttest, spec.Resource)
					if err != nil || id != current.ID {
						t.Fatalf("authorize=%s/%v want current=%s stale=%s", id, err, current.ID, stale.ID)
					}
					before := len(mustAudit(t, path))
					got, err := p.LocalAttest(req)
					if err != nil || !attestVerified(currentPub, req.Resource, req.Payload, got) || VerifyLocalAttestation(stalePub, req.Resource, req.Payload, got.Signature[:]) {
						t.Fatalf("current-key signature rejected or stale key accepted: %v", err)
					}
					rows := mustAudit(t, path)[before:]
					if len(rows) != 2 || rows[0].Action != actionLocalAttest || rows[0].Result != resultAllowed || rows[1].Result != resultCompleted || rows[0].GrantID != current.ID || rows[1].GrantID != current.ID {
						t.Fatalf("attestation audit does not name current grant: %+v", rows)
					}
				}
				reopen := func() {
					t.Helper()
					s.Lock()
					s, err = Unlock(path, pass, nil)
					if err != nil {
						t.Fatal(err)
					}
				}
				checkAllowed()
				reopen()
				checkAllowed()
				if outcome == "active" {
					if _, err := VerifyAudit(path, pass); err != nil {
						t.Fatal(err)
					}
					return
				}
				want := ErrDeniedRevoked
				result := resultDeniedRevoked
				if outcome == "revoked" {
					if err := s.RevokeGrant(current.ID); err != nil {
						t.Fatal(err)
					}
				} else {
					// Add a stale-key grant which is still active after the
					// current-key grant expires, using only public APIs.
					if _, err = s.Replace(cred.ID, staleDER, LifecycleOptions{}); err != nil {
						t.Fatal(err)
					}
					longSpec := spec
					longSpec.ExpiresAt = expires.Add(time.Hour)
					if _, err := s.IssueGrant(longSpec); err != nil {
						t.Fatal(err)
					}
					if _, err = s.Replace(cred.ID, currentDER, LifecycleOptions{}); err != nil {
						t.Fatal(err)
					}
					want, result = ErrDeniedExpired, resultDeniedExpired
					s.clock = func() time.Time { return expires }
				}
				for _, afterReopen := range []bool{false, true} {
					if afterReopen {
						reopen()
						if outcome == "expired" {
							s.clock = func() time.Time { return expires }
						}
					}
					p, err := s.Agent(agent.ID)
					if err != nil {
						t.Fatal(err)
					}
					id, err := p.Authorize(cred.ID, OpLocalArtifactAttest, spec.Resource)
					if id != "" || !errors.Is(err, want) {
						t.Fatalf("authorize lifecycle result=%s/%v want=%v", id, err, want)
					}
					before := len(mustAudit(t, path))
					got, err := p.LocalAttest(req)
					if got != (LocalAttestation{}) || !errors.Is(err, want) {
						t.Fatalf("sign lifecycle result=%v want=%v", err, want)
					}
					rows := mustAudit(t, path)[before:]
					if len(rows) < 1 || rows[0].Action != actionLocalAttest || rows[0].Result != result || rows[0].GrantID != current.ID {
						t.Fatalf("lifecycle audit does not name current grant: %+v", rows)
					}
				}
				if _, err := VerifyAudit(path, pass); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
