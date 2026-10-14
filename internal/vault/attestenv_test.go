package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"testing"
	"time"
)

// attestEnv is a single-user vault holding one Ed25519 credential and one
// agent. The passphrase holder issues the attestation grant directly; there
// is no second human and no approval step. See ADR 0015 (superseded).
type attestEnv struct {
	path, label, resource string
	pass, secret, der     []byte
	sentinel              string
	s                     *Session
	cred                  Credential
	agent                 Agent
	priv                  ed25519.PrivateKey
}

func newAttestEnv(t *testing.T) *attestEnv {
	t.Helper()
	return newAttestEnvLog(t, nil)
}

func newAttestEnvLog(t *testing.T, buf *bytes.Buffer) *attestEnv {
	t.Helper()
	var logger *log.Logger
	if buf != nil {
		logger = log.New(buf, "", 0)
	}
	path, pass, session := mustCreate(t, logger)
	env := &attestEnv{
		path: path, pass: pass, s: session,
		label:    "label-" + randHex(t, 16),
		resource: "artifact-" + randHex(t, 16),
		sentinel: "sentinel-" + randHex(t, 16),
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env.priv = priv
	env.secret = append([]byte(nil), derPlaceholder(t, priv)...)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	env.der = der
	env.cred, err = session.Put(env.label, CredTypeEd25519, der, PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	env.agent, err = session.CreateAgent("worker")
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// grantedAttestEnv is newAttestEnv with the attestation grant already issued.
func grantedAttestEnv(t *testing.T) *attestEnv {
	t.Helper()
	env := newAttestEnv(t)
	env.grant(t, time.Hour)
	return env
}

// grant issues one local_artifact_attest grant for this env's agent,
// credential, and resource.
func (e *attestEnv) grant(t *testing.T, life time.Duration) Grant {
	t.Helper()
	g, err := e.s.IssueGrant(e.grantSpec(life))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func (e *attestEnv) grantSpec(life time.Duration) GrantSpec {
	return GrantSpec{
		AgentID: e.agent.ID, CredentialID: e.cred.ID,
		Operations: []string{OpLocalArtifactAttest}, Resource: e.resource,
		ExpiresAt: time.Now().UTC().Add(life),
	}
}

// TestRetiredSharedStateFailsClosed pins the downgrade boundary left by the
// M9a removal: a sealed document that still carries organization, membership,
// request, or grant-provenance state must not open as an ordinary single-user
// vault with those restrictions dropped. See ADR 0015 (superseded).
func TestRetiredSharedStateFailsClosed(t *testing.T) {
	cases := map[string]func(string) string{
		"organization": func(doc string) string {
			return `{"organization":{"id":"ab","vault_id":"ab"},` + doc[1:]
		},
		"memberships": func(doc string) string {
			return `{"memberships":[{"human_id":"ab","role":"owner","generation":1,"state":"active"}],` + doc[1:]
		},
		"requests": func(doc string) string {
			return `{"requests":[{"id":"ab","status":"pending"}],` + doc[1:]
		},
		"grant provenance": func(doc string) string {
			return strings.Replace(doc, `"grants":[{`,
				`"grants":[{"provenance":{"request_id":"ab","org_id":"ab","requester_id":"a","requester_gen":1,"approver_id":"b","approver_gen":1},`, 1)
		},
	}
	for name, splice := range cases {
		t.Run(name, func(t *testing.T) {
			env := grantedAttestEnv(t)
			plain, err := json.Marshal(document{
				Credentials: env.s.creds, Agents: env.s.agents, Grants: env.s.grants,
				Detection: env.s.detection, HealthPolicy: env.s.hpolicy,
			})
			if err != nil {
				t.Fatal(err)
			}
			tampered := splice(string(plain))
			if tampered == string(plain) {
				t.Fatal("test did not splice retired state into the document")
			}
			nonce, ct, err := seal(env.s.dek, []byte(tampered), dataAAD(env.s.id, env.s.header.AuditHead, env.s.header.AuditSeq))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := env.s.db.Exec(`UPDATE vault SET data_nonce=?, encrypted_document=? WHERE id=?`, nonce, ct, env.s.id); err != nil {
				t.Fatal(err)
			}
			env.s.Lock()
			opened, err := Unlock(env.path, env.pass, nil)
			if !errors.Is(err, ErrCorrupt) {
				if opened != nil {
					opened.Lock()
				}
				t.Fatalf("retired shared state opened as a single-user vault: %v", err)
			}
		})
	}
}

type callChecker struct{ fn func() }

func (c callChecker) Lookup(CompromiseQuery) ([]string, error) {
	if c.fn != nil {
		fn := c.fn
		c.fn = nil
		fn()
	}
	return nil, nil
}

func derPlaceholder(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
