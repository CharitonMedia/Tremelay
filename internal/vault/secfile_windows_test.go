//go:build windows

package vault

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

var wellKnownSIDs = []windows.WELL_KNOWN_SID_TYPE{
	windows.WinWorldSid,
	windows.WinAuthenticatedUserSid,
	windows.WinBuiltinAdministratorsSid,
	windows.WinLocalSystemSid,
}

func TestExclusiveVaultFileOwnerOnlyDACL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	f, err := OpenExclusiveOwnerOnly(path, os.O_RDWR|os.O_CREATE|os.O_EXCL)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	self, err := CurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		t.Fatalf("read DACL: %v", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(self) {
		t.Fatalf("owner %v (%v)", owner, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL: %v", err)
	}
	if dacl.AceCount != 1 {
		t.Fatalf("DACL holds %d entries, want exactly one", dacl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	granted := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !granted.IsValid() || !granted.Equals(self) {
		t.Fatalf("grants %v, want %v", granted, self)
	}
	for _, kind := range wellKnownSIDs {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			t.Fatal(err)
		}
		if sid.Equals(self) {
			continue
		}
		if owner.Equals(sid) || granted.Equals(sid) {
			t.Fatalf("descriptor names %v", sid)
		}
	}
	if err := DescriptorIsUserOnly(sd, self); err != nil {
		t.Fatal(err)
	}
}
