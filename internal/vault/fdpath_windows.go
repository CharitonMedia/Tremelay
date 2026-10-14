//go:build windows

package vault

import (
	"os"

	"golang.org/x/sys/windows"
)

func sqlitePathForOpenFile(f *os.File) (string, error) {
	if f == nil {
		return "", ErrIO
	}
	handle := windows.Handle(f.Fd())
	size := uint32(256)
	for {
		buf := make([]uint16, size)
		n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], size, 0)
		if err != nil {
			if err == windows.ERROR_INSUFFICIENT_BUFFER {
				size = n + 1
				continue
			}
			return "", ErrIO
		}
		return windows.UTF16ToString(buf[:n]), nil
	}
}
