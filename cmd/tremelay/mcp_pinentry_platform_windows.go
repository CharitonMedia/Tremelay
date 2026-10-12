//go:build windows

package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
)

// The first Windows contract is a directly launched native GUI executable on
// a local drive. No shell, batch file, UNC/device path, or mapped network drive
// is accepted. The host must trust the executable and its DLL/plugin directory.
func validPinentryExecutable(path string) bool {
	volume := filepath.VolumeName(path)
	if !filepath.IsAbs(path) || len(volume) != 2 || volume[1] != ':' ||
		!strings.EqualFold(filepath.Ext(path), ".exe") || strings.Contains(path[2:], ":") {
		return false
	}
	root, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil {
		return false
	}
	switch windows.GetDriveType(root) {
	case windows.DRIVE_FIXED, windows.DRIVE_REMOVABLE, windows.DRIVE_RAMDISK:
		return true
	}
	return false
}

func pinentryPipeEnds(input, output *os.File) (io.WriteCloser, io.ReadCloser, error) {
	in, err := duplicateWindowsPipe(input)
	if err != nil {
		return nil, nil, err
	}
	out, err := duplicateWindowsPipe(output)
	if err != nil {
		in.Close()
		return nil, nil, err
	}
	// os.Pipe's parent ends are inheritable on Windows. Only the private
	// child ends remain in exec.Cmd's explicit inherited standard-handle list.
	input.Close()
	output.Close()
	return in, out, nil
}

func configurePinentry(cmd *exec.Cmd) {
	// Go supplies SYSTEMROOT, required for Windows process startup. Do not
	// inherit PATH, HOME, APPDATA, Qt plugin settings, or passphrase variables.
	cmd.Env = []string{}
	for _, key := range []string{"LANG", "LC_CTYPE", "LC_MESSAGES"} {
		if value, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	cmd.Dir = filepath.Dir(cmd.Path)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
}

func pinentryTerminal(selected string) (func() error, string, error) {
	if selected != "" {
		return nil, "", errPinentryUnavailable // No Unix tty emulation.
	}
	if _, err := windows.GetConsoleCP(); err != nil {
		if err == windows.ERROR_INVALID_HANDLE {
			// GUI helpers can operate without an attached console. Their own
			// display failure still fails the bounded Assuan exchange closed.
			return func() error { return nil }, "", nil
		}
		return nil, "", errPinentryUnavailable
	}
	type consoleState struct {
		handle windows.Handle
		mode   uint32
	}
	var states []consoleState
	for _, name := range []string{"CONIN$", "CONOUT$"} {
		p, _ := windows.UTF16PtrFromString(name)
		h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
		var mode uint32
		if err == nil {
			err = windows.GetConsoleMode(h, &mode)
		}
		if err != nil {
			if h != 0 && h != windows.InvalidHandle {
				windows.CloseHandle(h)
			}
			for _, state := range states {
				windows.CloseHandle(state.handle)
			}
			return nil, "", errPinentryUnavailable
		}
		states = append(states, consoleState{h, mode})
	}
	var once sync.Once
	var result error
	return func() error {
		once.Do(func() {
			for _, state := range states {
				if windows.SetConsoleMode(state.handle, state.mode) != nil {
					result = errPinentryTerminal
				}
				if windows.CloseHandle(state.handle) != nil {
					result = errPinentryTerminal
				}
			}
		})
		return result
	}, "", nil
}
