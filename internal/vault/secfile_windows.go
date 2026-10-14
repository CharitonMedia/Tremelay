//go:build windows

package vault

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrSecureCreateACL means the filesystem did not retain an owner-only DACL.
var ErrSecureCreateACL = errors.New("owner-only security descriptor was not applied")

const ownerOnlyFileRights = "GA"

const maxDescriptorACEs = 64

// CurrentUserSID returns this process's interactive user SID.
func CurrentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid.Copy()
}

// OwnerOnlySecurityDescriptor grants rights only to the current user, with a
// protected DACL that inherits nothing.
func OwnerOnlySecurityDescriptor(rights string) (*windows.SECURITY_DESCRIPTOR, error) {
	sid, err := CurrentUserSID()
	if err != nil {
		return nil, err
	}
	self := sid.String()
	return windows.SecurityDescriptorFromString("O:" + self + "G:" + self + "D:P(A;;" + rights + ";;;" + self + ")")
}

// DescriptorIsUserOnly requires the owner and every DACL entry to name self.
func DescriptorIsUserOnly(sd *windows.SECURITY_DESCRIPTOR, self *windows.SID) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(self) {
		return ErrSecureCreateACL
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 || dacl.AceCount > maxDescriptorACEs {
		return ErrSecureCreateACL
	}
	for index := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return ErrSecureCreateACL
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || !sid.Equals(self) {
			return ErrSecureCreateACL
		}
	}
	return nil
}

// OpenExclusiveOwnerOnly creates path with O_EXCL and an owner-only DACL.
func OpenExclusiveOwnerOnly(path string, flag int) (*os.File, error) {
	return openExclusiveOwnerOnly(path, flag)
}

// VerifyOwnerOnlyHandle requires the open object's DACL to name only self.
func VerifyOwnerOnlyHandle(handle windows.Handle) error {
	return verifyOwnerOnlyHandle(handle)
}

func openExclusiveOwnerOnly(path string, flag int) (*os.File, error) {
	sd, err := OwnerOnlySecurityDescriptor(ownerOnlyFileRights)
	if err != nil {
		return nil, ErrIO
	}
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrIO
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	access := windowsAccess(flag)
	handle, err := windows.CreateFile(wide, access, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return nil, os.ErrExist
		}
		return nil, ErrIO
	}
	if err := verifyOwnerOnlyHandle(handle); err != nil {
		windows.CloseHandle(handle)
		os.Remove(path)
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, ErrIO
	}
	return file, nil
}

func verifyOwnerOnlyHandle(handle windows.Handle) error {
	self, err := CurrentUserSID()
	if err != nil {
		return ErrSecureCreateACL
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil || DescriptorIsUserOnly(sd, self) != nil {
		return ErrSecureCreateACL
	}
	return nil
}

// VerifyOwnerOnlyPath refuses a path whose DACL names any principal but self.
func VerifyOwnerOnlyPath(path string) error {
	self, err := CurrentUserSID()
	if err != nil {
		return ErrSecureCreateACL
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return ErrSecureCreateACL
	}
	return DescriptorIsUserOnly(sd, self)
}

func windowsAccess(flag int) uint32 {
	access := uint32(windows.READ_CONTROL)
	if flag&os.O_WRONLY != 0 {
		access |= windows.GENERIC_WRITE
	}
	if flag&os.O_RDWR != 0 {
		access |= windows.GENERIC_READ | windows.GENERIC_WRITE
	}
	if flag&os.O_RDONLY != 0 && flag&os.O_RDWR == 0 && flag&os.O_WRONLY == 0 {
		access |= windows.GENERIC_READ
	}
	return access
}
