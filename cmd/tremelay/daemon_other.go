//go:build !linux && !darwin && !windows

package main

import (
	"net"
	"os"
)

// Fail closed until a user-only endpoint and an independent peer-identity
// check have been implemented and exercised natively on this platform.
// Every other CLI command, including `tremelay mcp serve`, stays buildable.
func daemonListen(func(string) string) (net.Listener, string, error) {
	return nil, "", errDaemonEndpoint
}

func daemonDial(func(string) string) (net.Conn, error) { return nil, errDaemonEndpoint }

func daemonPeerAllowed(net.Conn) bool { return false }

func userOnlyFile(string) error { return errAgentToken }

func createUserOnlyFile(string) (*os.File, error) { return nil, errAgentToken }
