//go:build !windows

package vault

import (
	"errors"
	"os"
)

// ErrSecureCreateACL is returned on Windows when an owner-only descriptor
// could not be applied. It is never returned on Unix-like systems.
var ErrSecureCreateACL = errors.New("owner-only security descriptor was not applied")

// OpenExclusiveOwnerOnly creates path with O_EXCL and mode 0600 on Unix.
func OpenExclusiveOwnerOnly(path string, flag int) (*os.File, error) {
	return openExclusiveOwnerOnly(path, flag)
}

func openExclusiveOwnerOnly(path string, flag int) (*os.File, error) {
	f, err := os.OpenFile(path, flag, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, os.ErrExist
		}
		return nil, ErrIO
	}
	return f, nil
}
