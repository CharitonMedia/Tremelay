//go:build windows

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/CharitonMedia/Tremelay/internal/vault"
	"golang.org/x/sys/windows"
)

// daemonTestEnv gives one test its own pipe instance beside the per-user name.
func daemonTestEnv(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{daemonInstanceEnv: randHex(t, 8)}
}

// wellKnownSIDs are the principals a shared machine carries that the endpoint
// must not admit: Everyone, Authenticated Users, Administrators and SYSTEM.
var wellKnownSIDs = []windows.WELL_KNOWN_SID_TYPE{
	windows.WinWorldSid,
	windows.WinAuthenticatedUserSid,
	windows.WinBuiltinAdministratorsSid,
	windows.WinLocalSystemSid,
}

// TestDaemonPipeDescriptorIsOwnerOnly reads the descriptor the daemon creates
// its pipe with: this user owns it, one entry grants this user
// GENERIC_READ|GENERIC_WRITE, and no other principal is named at all.
func TestDaemonPipeDescriptorIsOwnerOnly(t *testing.T) {
	self, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := userOnlyDescriptor(pipeRights)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(self) {
		t.Fatalf("endpoint owner is %v (%v)", owner, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("endpoint has no DACL: %v", err)
	}
	if dacl.AceCount != 1 {
		t.Fatalf("endpoint DACL holds %d entries, want exactly one", dacl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		t.Fatalf("endpoint entry type %d", ace.Header.AceType)
	}
	if ace.Mask != windows.GENERIC_READ|windows.GENERIC_WRITE {
		t.Fatalf("endpoint grants mask %#x, want GENERIC_READ|GENERIC_WRITE", uint32(ace.Mask))
	}
	granted := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !granted.IsValid() || !granted.Equals(self) {
		t.Fatalf("endpoint grants %v, want %v", granted, self)
	}
	for _, kind := range wellKnownSIDs {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			t.Fatal(err)
		}
		if sid.Equals(self) {
			continue // Only this user's own SID may appear.
		}
		if owner.Equals(sid) || granted.Equals(sid) {
			t.Fatalf("the endpoint descriptor names %v", sid)
		}
	}
	if err := descriptorIsUserOnly(sd, self); err != nil {
		t.Fatalf("the descriptor this daemon writes fails its own check: %v", err)
	}
}

// TestDaemonPipeNameIsClaimedExclusively proves the squatting defence in both
// directions: while one daemon holds the name no second daemon can start on
// it, and the name is reusable once released.
func TestDaemonPipeNameIsClaimedExclusively(t *testing.T) {
	getenv := envGet(daemonTestEnv(t))
	listener, endpoint, err := daemonListen(getenv)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if !strings.HasPrefix(endpoint, daemonPipePrefix) {
		t.Fatalf("endpoint %q is not a per-user pipe name", endpoint)
	}
	if _, _, err := daemonListen(getenv); err != errDaemonRunning {
		t.Fatalf("second daemon on the same pipe name: %v", err)
	}
	listener.Close()
	again, _, err := daemonListen(getenv)
	if err != nil {
		t.Fatalf("released pipe name was not reusable: %v", err)
	}
	again.Close()
}

// TestDaemonPipeNameRejectsUnsafeInstance keeps the instance label from
// naming anything outside this user's pipe, and checks that an endpoint which
// cannot be formed stops the daemon before it asks for a passphrase.
func TestDaemonPipeNameRejectsUnsafeInstance(t *testing.T) {
	for _, label := range []string{"has space", "..", `one\two`, "one/two", "a:b", strings.Repeat("x", maxInstanceLabel+1)} {
		if name := daemonEndpoint(envGet(map[string]string{daemonInstanceEnv: label})); name != "" {
			t.Fatalf("instance label %q produced endpoint %q", label, name)
		}
	}
	assertEndpointRefusesPassphrase(t, map[string]string{daemonInstanceEnv: "not a label"})
}

// TestAgentTokenFileRefusesWiderDACL widens a token file's DACL to Everyone
// the way an inherited profile permission would, and requires the refusal
// that the Unix group/other mode check makes.
func TestAgentTokenFileRefusesWiderDACL(t *testing.T) {
	self, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	if everyone.Equals(self) {
		t.Fatal("this process runs as Everyone")
	}
	path := filepath.Join(t.TempDir(), "agent.token")
	if err := writeAgentToken(path, randBytes(t, vault.AgentTokenLen)); err != nil {
		t.Fatal(err)
	}
	if _, err := readAgentToken(path); err != nil {
		t.Fatalf("a token file this command wrote was refused: %v", err)
	}
	wider, err := windows.SecurityDescriptorFromString(
		"D:P(A;;GA;;;" + self.String() + ")(A;;GR;;;" + everyone.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := wider.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := readAgentToken(path); err != errAgentToken {
		t.Fatalf("a token file Everyone can read was accepted: %v", err)
	}
}

// TestSSHAgentFailsClosedOnWindows pins the one daemon command this platform
// does not carry. See ADR 0024.
func TestSSHAgentFailsClosedOnWindows(t *testing.T) {
	var stdout, stderr bytes.Buffer
	tokenFile := filepath.Join(t.TempDir(), "agent.token")
	if err := writeAgentToken(tokenFile, randBytes(t, vault.AgentTokenLen)); err != nil {
		t.Fatal(err)
	}
	code := run([]string{"ssh-agent", "--token-file", tokenFile}, envGet(daemonTestEnv(t)),
		strings.NewReader(""), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), errSSHAgentPlatform.Error()) {
		t.Fatalf("ssh-agent exited %d: %q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("ssh-agent published an endpoint: %q", stdout.String())
	}
}
