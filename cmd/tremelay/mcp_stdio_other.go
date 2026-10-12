//go:build !linux && !darwin

package main

import (
	"io"
	"os"
)

// Fail closed until interruptible process-pipe and terminal cleanup semantics
// have been implemented and exercised on this platform.
type mcpStdio struct{ in, out *os.File }

func openMCPStdio(io.Reader, io.Writer) (*mcpStdio, error) { return nil, errMCPStdio }
func (s *mcpStdio) close()                                 {}
func (s *mcpStdio) watchDisconnect(func()) func()          { return func() {} }
func pinentryTerminal(string) (func() error, string, error) {
	return nil, "", errPinentryUnavailable
}
