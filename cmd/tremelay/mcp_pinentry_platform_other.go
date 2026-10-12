//go:build !windows

package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

func validPinentryExecutable(path string) bool { return filepath.IsAbs(path) }

func pinentryPipeEnds(input, output *os.File) (io.WriteCloser, io.ReadCloser, error) {
	return input, output, nil
}

func configurePinentry(cmd *exec.Cmd) {
	// UI discovery only; never inherit passphrase or arbitrary host settings.
	cmd.Env = []string{}
	for _, key := range []string{"HOME", "TERM", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "LANG", "LC_CTYPE", "LC_MESSAGES"} {
		if value, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
}
