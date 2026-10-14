package vault

import (
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"
)

// These tests are the vault half of V1.md item 3d and carry no socket, no
// process and no platform assumption, so Windows runs them too.

// TestSessionAdoptsControlPlaneCommits is the acceptance path. An unlocked
// session picks up grants another holder of the same passphrase creates and
// revokes, with no passphrase of its own and no reopening, and the capability
// a bound agent already holds follows that authority both ways.
func TestSessionAdoptsControlPlaneCommits(t *testing.T) {
	env := newAttestEnv(t)
	first := env.grant(t, time.Hour)
	cap := bindCap(t, env.s, env.agent.ID)
	control, err := Unlock(env.path, env.pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(control.Lock)

	listed := capCall(t, cap, okBytes(t)(encodeCapList())).entries
	if len(listed) != 1 || listed[0].resource != env.resource {
		t.Fatalf("the bound capability does not hold its grant: %+v", listed)
	}
	handle := listed[0].handle

	// An agent created elsewhere is authenticable here, which is what lets a
	// human register an agent while the daemon serves.
	added, err := control.CreateAgent("second worker")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.s.Agent(added.ID); err != nil {
		t.Fatalf("an agent created by the control plane is unknown: %v", err)
	}

	// A grant created elsewhere is usable on the next call.
	second := "artifact-" + randHex(t, 16)
	spec := env.grantSpec(time.Hour)
	spec.Resource = second
	if _, err := control.IssueGrant(spec); err != nil {
		t.Fatal(err)
	}
	listed = capCall(t, cap, okBytes(t)(encodeCapList())).entries
	if len(listed) != 2 {
		t.Fatalf("a grant created by the control plane is not usable: %+v", listed)
	}
	if got := capCall(t, cap, okBytes(t)(encodeCapInvoke(handle, []byte("adopted")))); got.code != "" {
		t.Fatalf("an unchanged grant stopped working: %q", got.code)
	}

	// A grant revoked elsewhere is refused on the next call, through the
	// handle the agent already holds.
	if err := control.RevokeGrant(first.ID); err != nil {
		t.Fatal(err)
	}
	if got := capCall(t, cap, okBytes(t)(encodeCapInvoke(handle, []byte("revoked")))); got.code != capDeniedRevoked {
		t.Fatalf("a revoked grant was not refused: %q", got.code)
	}
	for _, entry := range capCall(t, cap, okBytes(t)(encodeCapList())).entries {
		if entry.resource == second && entry.status != GrantActive {
			t.Fatalf("the surviving grant is %q", entry.status)
		}
		if entry.resource == env.resource && entry.status != GrantRevoked {
			t.Fatalf("the revoked grant is still %q", entry.status)
		}
	}
	if _, err := VerifyAudit(env.path, env.pass); err != nil {
		t.Fatalf("audit chain invalid: %v", err)
	}
}

func TestSessionAdoptsLockedDenialSuffix(t *testing.T) {
	for _, name := range []string{"human", "agent"} {
		t.Run(name, func(t *testing.T) {
			env := newAttestEnv(t)
			use := func() {
				if _, err := env.s.List(); err != nil {
					t.Fatal(err)
				}
			}
			if name == "agent" {
				cap := bindCap(t, env.s, env.agent.ID)
				use = func() {
					if got := capCall(t, cap, okBytes(t)(encodeCapList())); got.code != "" {
						t.Fatalf("capability list failed: %q", got.code)
					}
				}
			}
			before := len(mustAudit(t, env.path))
			if unlocked, err := Unlock(env.path, []byte(randHex(t, 24)), nil); unlocked != nil || !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("wrong passphrase unlocked: %v", err)
			}

			use()

			events := mustAudit(t, env.path)
			if len(events) < before+2 || events[before].Action != actionUnlock || events[before].Result != resultDenied {
				t.Fatalf("locked denial was not incorporated before the resident operation: %+v", events[before:])
			}
			if env.s.header.AuditSeq != events[len(events)-1].Seq {
				t.Fatalf("resident head %d, audit tip %d", env.s.header.AuditSeq, events[len(events)-1].Seq)
			}
			if _, err := VerifyAudit(env.path, env.pass); err != nil {
				t.Fatalf("audit chain invalid: %v", err)
			}
		})
	}
}

func TestSessionRefusesForgedLockedSuffix(t *testing.T) {
	env := newAttestEnv(t)
	events := mustAudit(t, env.path)
	forged, err := nextEvent(events, actionList, env.s.id, "", "", resultAllowed)
	if err != nil {
		t.Fatal(err)
	}
	mutateDB(t, env.path, func(db *sql.DB) {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err := insertAudit(tx, forged); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	})

	if _, err := env.s.List(); !errors.Is(err, ErrAudit) {
		t.Fatalf("forged suffix did not fail closed: %v", err)
	}
	if _, err := env.s.List(); !errors.Is(err, ErrStale) {
		t.Fatalf("retired session still served: %v", err)
	}
}

func TestAuditSequenceCollisionIsAuditFailure(t *testing.T) {
	env := newAttestEnv(t)
	events := mustAudit(t, env.path)
	tx, err := env.s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := insertAudit(tx, events[len(events)-1]); !errors.Is(err, ErrAudit) {
		t.Fatalf("sequence collision: %v", err)
	}
}

// TestSessionReloadFailsClosed covers the other half: a reload is adopted only
// when it verifies exactly as Unlock does. Each case moves the durable
// sequence with a legitimate commit and then corrupts what the session must
// re-verify, so the session reaches the damage through the reload path.
func TestSessionReloadFailsClosed(t *testing.T) {
	cases := map[string]struct {
		damage func(*testing.T, *attestEnv, *sql.DB)
		want   error
	}{
		"tampered document": {
			damage: func(t *testing.T, env *attestEnv, db *sql.DB) {
				execSQL(t, db, `UPDATE vault SET encrypted_document = randomblob(length(encrypted_document))`)
			},
			want: ErrCorrupt,
		},
		"broken chain": {
			damage: func(t *testing.T, env *attestEnv, db *sql.DB) {
				execSQL(t, db, `UPDATE audit SET result = 'denied' WHERE seq = 2`)
			},
			want: ErrAudit,
		},
		"rolled back audit head": {
			damage: func(t *testing.T, env *attestEnv, db *sql.DB) {
				execSQL(t, db, `DELETE FROM audit WHERE seq = (SELECT MAX(seq) FROM audit)`)
			},
			want: ErrAudit,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			env := grantedAttestEnv(t)
			control, err := Unlock(env.path, env.pass, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := control.CreateAgent("second worker"); err != nil {
				t.Fatal(err)
			}
			control.Lock()
			mutateDB(t, env.path, func(db *sql.DB) { tc.damage(t, env, db) })

			if _, err := env.s.CreateAgent("third worker"); !errors.Is(err, tc.want) {
				t.Fatalf("damaged reload: %v, want %v", err, tc.want)
			}
			// A session that could not verify the file is retired, not
			// merely failed for one call: it must not sign, approve or
			// restore from the view it still holds in memory.
			if _, err := env.s.List(); !errors.Is(err, ErrStale) {
				t.Fatalf("retired session still served: %v", err)
			}
			if _, err := env.s.Agent(env.agent.ID); !errors.Is(err, ErrStale) {
				t.Fatalf("retired session still bound an agent: %v", err)
			}
		})
	}
}

// TestSessionRefusesForkedChain is the rollback a sequence comparison cannot
// see. An attacker restores an older authentic copy of the vault file and
// lets the owner's own later commands push it past the sequence this session
// has already served: the header, the chain, the suffix and the sealed
// document all verify, because they are this vault's, just not this history.
// The only thing that can refuse it is the session's memory of the tip it
// verified, so that is what the reload requires the new chain to contain.
func TestSessionRefusesForkedChain(t *testing.T) {
	env := newAttestEnv(t)
	grant := env.grant(t, time.Hour)
	cap := bindCap(t, env.s, env.agent.ID)
	handle := capCall(t, cap, okBytes(t)(encodeCapList())).entries[0].handle

	// The copy an attacker keeps: the vault as it is before the revocation.
	var nonce, doc []byte
	var head string
	var seq int64
	mutateDB(t, env.path, func(db *sql.DB) {
		if err := db.QueryRow(`SELECT data_nonce, encrypted_document, audit_head, audit_seq FROM vault`).Scan(&nonce, &doc, &head, &seq); err != nil {
			t.Fatal(err)
		}
	})
	control, err := Unlock(env.path, env.pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.RevokeGrant(grant.ID); err != nil {
		t.Fatal(err)
	}
	control.Lock()
	// The session adopts the revocation. That tip is what it must not lose.
	if got := capCall(t, cap, okBytes(t)(encodeCapInvoke(handle, []byte("revoked")))); got.code != capDeniedRevoked {
		t.Fatalf("the revocation was not adopted: %q", got.code)
	}
	tip := env.s.header.AuditSeq

	// Restore the copy, then let ordinary unlocks push the fork past that
	// tip, which is all the attacker needs from the owner.
	mutateDB(t, env.path, func(db *sql.DB) {
		execSQL(t, db, `DELETE FROM audit WHERE seq > ?`, seq)
		execSQL(t, db, `UPDATE vault SET data_nonce=?, encrypted_document=?, audit_head=?, audit_seq=?`, nonce, doc, head, seq)
	})
	for forked := uint64(seq); forked <= tip; {
		owner, err := Unlock(env.path, env.pass, nil)
		if err != nil {
			t.Fatal(err)
		}
		forked = owner.header.AuditSeq
		owner.Lock()
	}

	// The fork is never adopted, so the revoked grant is not active again,
	// and the session is retired rather than left serving either view.
	if raw, err := cap.Exchange(okBytes(t)(encodeCapList())); raw != nil || !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a forked chain was adopted: %x %v", raw, err)
	}
	if _, err := env.s.List(); !errors.Is(err, ErrStale) {
		t.Fatalf("retired session still served: %v", err)
	}
}

func TestSessionRefusesSameSequenceFork(t *testing.T) {
	env := newAttestEnv(t)
	grant := env.grant(t, time.Hour)
	cap := bindCap(t, env.s, env.agent.ID)
	handle := capCall(t, cap, okBytes(t)(encodeCapList())).entries[0].handle

	// Keep an authentic copy, then advance the resident session's branch
	// without changing the grant.
	var nonce, doc []byte
	var head string
	var seq int64
	mutateDB(t, env.path, func(db *sql.DB) {
		if err := db.QueryRow(`SELECT data_nonce, encrypted_document, audit_head, audit_seq FROM vault`).Scan(&nonce, &doc, &head, &seq); err != nil {
			t.Fatal(err)
		}
	})
	for range 2 {
		if _, err := env.s.List(); err != nil {
			t.Fatal(err)
		}
	}

	// Restore the copy. Unlock and revoke advance this branch to the same
	// sequence as the resident branch, but with a different audit head.
	mutateDB(t, env.path, func(db *sql.DB) {
		execSQL(t, db, `DELETE FROM audit WHERE seq > ?`, seq)
		execSQL(t, db, `UPDATE vault SET data_nonce=?, encrypted_document=?, audit_head=?, audit_seq=?`, nonce, doc, head, seq)
	})
	owner, err := Unlock(env.path, env.pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.RevokeGrant(grant.ID); err != nil {
		t.Fatal(err)
	}
	if owner.header.AuditSeq != env.s.header.AuditSeq || owner.header.AuditHead == env.s.header.AuditHead {
		t.Fatalf("fork tips: resident %d %s, durable %d %s",
			env.s.header.AuditSeq, env.s.header.AuditHead, owner.header.AuditSeq, owner.header.AuditHead)
	}
	owner.Lock()

	// Equality of sequence numbers must not let the resident release a
	// signature under the grant revoked on the durable branch.
	payload := []byte("same-sequence-fork-" + randHex(t, 16))
	if raw, err := cap.Exchange(okBytes(t)(encodeCapInvoke(handle, payload))); raw != nil || !errors.Is(err, ErrCorrupt) {
		t.Fatalf("same-sequence fork released a signature: %x %v", raw, err)
	}
	if _, err := env.s.List(); !errors.Is(err, ErrStale) {
		t.Fatalf("retired session still served: %v", err)
	}
	if _, err := VerifyAudit(env.path, env.pass); err != nil {
		t.Fatalf("durable revoked branch was changed: %v", err)
	}
}

// TestSessionReloadUnderConcurrentCalls runs the session's own entry points
// against each other while another holder commits, which is where a reload
// swaps the credential, grant and audit state underneath them. Under -race
// this is the check that the swap is never half observed.
func TestSessionReloadUnderConcurrentCalls(t *testing.T) {
	env := grantedAttestEnv(t)
	control, err := Unlock(env.path, env.pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(control.Lock)
	caps := []*AgentCapability{
		bindCap(t, env.s, env.agent.ID),
		bindCap(t, env.s, env.agent.ID),
	}

	stop := make(chan struct{})
	var callers sync.WaitGroup
	for _, cap := range caps {
		callers.Add(1)
		go func() {
			defer callers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				resp, err := cap.Exchange(okBytes(t)(encodeCapList()))
				if errors.Is(err, ErrStale) {
					// This call's own audit row lost the race to a
					// concurrent commit. Nothing was written and the
					// session adopts that commit at the next entry.
					continue
				}
				if err != nil {
					t.Errorf("capability call during a reload: %v", err)
					return
				}
				decoded, err := decodeCapResponse(resp)
				if err != nil {
					t.Errorf("capability response during a reload: %v", err)
					return
				}
				// The grant this agent holds is never missing, whichever
				// side of a reload the call lands on.
				if len(decoded.entries) == 0 || decoded.entries[0].resource != env.resource {
					t.Errorf("a reload hid a live grant: %+v", decoded.entries)
					return
				}
			}
		}()
	}
	callers.Add(1)
	go func() {
		defer callers.Done()
		for range 5 {
			if _, err := env.s.CreateAgent("local-" + randHex(t, 8)); err != nil && !errors.Is(err, ErrStale) {
				t.Errorf("concurrent local commit: %v", err)
				return
			}
		}
	}()
	for range 5 {
		// A commit from the other holder is what forces the reload.
		if _, err := control.CreateAgent("remote-" + randHex(t, 8)); err != nil && !errors.Is(err, ErrStale) {
			// Stop the callers first, so cleanup's Lock does not show up as
			// their own spurious "vault unlock failed".
			close(stop)
			callers.Wait()
			t.Fatalf("concurrent control-plane commit: %v", err)
		}
	}
	close(stop)
	callers.Wait()
	if _, err := VerifyAudit(env.path, env.pass); err != nil {
		t.Fatalf("audit chain invalid: %v", err)
	}
}

func execSQL(t *testing.T, db *sql.DB, stmt string, args ...any) {
	t.Helper()
	if _, err := db.Exec(stmt, args...); err != nil {
		t.Fatal(err)
	}
}
