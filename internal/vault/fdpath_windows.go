//go:build windows

package vault

import (
	"os"
	"strings"

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
		if n >= size { // buffer too small: n is the required length
			size = n + 1
			continue
		}
		// Final paths come back as \\?\C:\... or \\?\UNC\server\share\...;
		// SQLite's file: URI wants the ordinary spelling.
		p := windows.UTF16ToString(buf[:n])
		if rest, ok := strings.CutPrefix(p, `\\?\UNC\`); ok {
			return `\\` + rest, nil
		}
		return strings.TrimPrefix(p, `\\?\`), nil
	}
}
