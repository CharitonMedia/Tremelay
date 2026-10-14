//go:build !linux && !darwin

package main

import "net"

// Fail closed until a user-only endpoint and an independent peer-identity
// check have been implemented and exercised natively on this platform.
// Windows named-pipe custody is deferred; see docs/adr/0024-headless-unlock-daemon.md.
// Every other CLI command, including `tremelay mcp serve`, stays buildable.
func daemonEndpoint(func(string) string) string { return "" }

func daemonListen(func(string) string) (net.Listener, string, error) {
	return nil, "", errDaemonEndpoint
}

func daemonDial(func(string) string) (net.Conn, error) { return nil, errDaemonEndpoint }

func daemonPeerAllowed(net.Conn, int) bool { return false }
