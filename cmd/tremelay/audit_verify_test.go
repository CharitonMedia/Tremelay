package main

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

func TestCLIAuditVerifyReadOnly(t *testing.T) {
	for _, schema := range []string{"current", "M1", "M2-M4", "M5"} {
		t.Run(schema, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vault.db")
			pass := randHex(t, 16)
			session, err := vault.Create(path, []byte(pass), nil)
			if err != nil {
				t.Fatal(err)
			}
			if schema != "M1" {
				if _, err := session.CreateAgent("legacy"); err != nil {
					t.Fatal(err)
				}
			}
			session.Lock()
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			var tip string
			if err := db.QueryRow(`SELECT hash FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&tip); err != nil {
				t.Fatal(err)
			}
			if schema != "current" {
				cols := "seq,time,action,vault_id,credential_id,credential_type,result,prev_hash,hash"
				if schema != "M1" {
					cols += ",agent_id,grant_id,operation"
				}
				if schema == "M5" {
					cols += ",v,class,ref_seq"
				}
				for _, stmt := range []string{
					`CREATE TABLE audit_legacy AS SELECT ` + cols + ` FROM audit`,
					`DROP TABLE audit`,
					`ALTER TABLE audit_legacy RENAME TO audit`,
				} {
					if _, err := db.Exec(stmt); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			check := func(passphrase string, wantOK bool) {
				t.Helper()
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var stdout, stderr bytes.Buffer
				code := run([]string{"audit", "verify", "--path", path}, envGet(map[string]string{"TREMELAY_PASSPHRASE": passphrase}), strings.NewReader(""), &stdout, &stderr)
				if (code == 0) != wantOK {
					t.Fatalf("verify exit %d: %s", code, stderr.String())
				}
				if wantOK && strings.TrimSpace(stdout.String()) != tip || !wantOK && stdout.Len() != 0 {
					t.Fatalf("unexpected verify stdout %q", stdout.String())
				}
				if len(passphrase) >= 8 && strings.Contains(stdout.String()+stderr.String(), passphrase) {
					t.Fatal("verification disclosed passphrase")
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatalf("verification changed the vault: %v", err)
				}
				files, err := os.ReadDir(filepath.Dir(path))
				if err != nil || len(files) != 1 || files[0].Name() != "vault.db" {
					t.Fatalf("verification left extra files: %v", err)
				}
			}
			// A rejected passphrase must not migrate the legacy schema either.
			check(randHex(t, 16), false)
			check("short", false)
			if err := os.Chmod(path, 0o400); err != nil {
				t.Fatal(err)
			}
			check(pass, true)
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			db, err = sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`UPDATE audit SET result='denied' WHERE seq=1`); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			check(pass, false)
		})
	}
}
