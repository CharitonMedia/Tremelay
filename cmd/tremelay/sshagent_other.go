//go:build !linux && !darwin

package main

import (
	"errors"
	"fmt"
	"io"
)

// ssh-agent is out of scope on Windows and every other non-Unix platform.
// It needs a listening endpoint and a peer-identity check of its own, and the
// SSH clients that would consume it speak a different transport there, so the
// command refuses rather than publishing an endpoint nothing has vouched for.
// `tremelay mcp --daemon` is unaffected. See ADR 0024 and ADR 0026.
var errSSHAgentPlatform = errors.New("ssh-agent is not available on this platform; agents reach the daemon with mcp --daemon")

func cmdSSHAgent(_ []string, _ func(string) string, _, stderr io.Writer) int {
	fmt.Fprintln(stderr, errSSHAgentPlatform.Error())
	return 1
}
