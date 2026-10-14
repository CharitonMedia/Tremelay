//go:build !windows

package vault

import (
	"fmt"
	"os"
	"runtime"
)

func sqlitePathForOpenFile(f *os.File) (string, error) {
	if f == nil {
		return "", ErrIO
	}
	fd := f.Fd()
	if runtime.GOOS == "linux" {
		return fmt.Sprintf("/proc/self/fd/%d", fd), nil
	}
	return fmt.Sprintf("/dev/fd/%d", fd), nil
}
