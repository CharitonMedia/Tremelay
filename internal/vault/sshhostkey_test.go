package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"filippo.io/edwards25519"
)

// The encodings of the eight small-order points, each with either sign bit
// where that gives a second encoding. crypto/ed25519.Verify accepts them as
// public keys.
var smallOrderEd25519Keys = []string{
	"0100000000000000000000000000000000000000000000000000000000000000",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
}

// A pinned host key of small order pins nothing: a signature anyone can write
// verifies under it, so any caller could bind any session and get a login
// signature good on any server. Issuance refuses such a key, and a grant that
// already holds one never binds.
func TestSSHHostKeyOfSmallOrderIsRefused(t *testing.T) {
	env := newSSHEnv(t)
	spec := func(host []byte) GrantSpec {
		return GrantSpec{
			AgentID: env.agent.ID, CredentialID: env.cred.ID, Operations: []string{OpSSHUserAuth},
			Resource: env.resource, ExpiresAt: time.Now().Add(time.Hour).UTC(),
			SSHUsername: env.user, SSHHostKey: marshalEd25519Pub(host),
		}
	}
	distinct := map[[32]byte]bool{}
	for _, encoded := range smallOrderEd25519Keys {
		key, err := hex.DecodeString(encoded)
		if err != nil || len(key) != ed25519.PublicKeySize {
			t.Fatalf("fixture %s", encoded)
		}
		// The fixture really is a small-order point, by the library's own
		// arithmetic, and not this file's say-so.
		p, err := new(edwards25519.Point).SetBytes(key)
		if err != nil {
			t.Fatalf("%s is not a point: %v", encoded, err)
		}
		if new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) != 1 {
			t.Fatalf("%s is not of small order", encoded)
		}
		distinct[[32]byte(p.Bytes())] = true
		if strongEd25519Key(key) {
			t.Errorf("%s accepted as a strong key", encoded)
		}
		if _, err := env.session.IssueGrant(spec(key)); !errors.Is(err, ErrInvalid) {
			t.Errorf("grant pinning %s: %v, want ErrInvalid", encoded, err)
		}
		// The forgery: R is the identity and S is zero.
		forged := make([]byte, ed25519.SignatureSize)
		forged[0] = 1
		if verifyHostBind(marshalEd25519Pub(key), bytes.Repeat([]byte{7}, 32), marshalEd25519Sig(forged)) {
			t.Errorf("a forged binding verified under %s", encoded)
		}
	}
	if len(distinct) != 8 {
		t.Fatalf("fixtures cover %d of the 8 small-order points", len(distinct))
	}
	// An off-curve value is refused too.
	off := bytes.Repeat([]byte{0xff}, 32)
	off[0] = 0x02
	if _, err := new(edwards25519.Point).SetBytes(off); err == nil {
		t.Skip("fixture is on the curve")
	} else if _, err := env.session.IssueGrant(spec(off)); !errors.Is(err, ErrInvalid) {
		t.Errorf("grant pinning an off-curve key: %v", err)
	}
	// A real host key is accepted and binds.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strongEd25519Key(pub) {
		t.Fatal("a generated key was refused")
	}
	if _, err := env.session.IssueGrant(spec(pub)); err != nil {
		t.Fatalf("grant pinning a real host key: %v", err)
	}
	sid := bytes.Repeat([]byte{9}, 32)
	if !verifyHostBind(marshalEd25519Pub(pub), sid, marshalEd25519Sig(ed25519.Sign(priv, sid))) {
		t.Fatal("a real host signature did not verify")
	}
}
