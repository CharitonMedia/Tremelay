package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

const sshAgentUsage = "usage: tremelay ssh-agent --token-file PATH [--socket /absolute/path]"

var errSSHAgentRelay = errors.New("ssh-agent connection refused; the daemon holds the reason in its audit chain")

func cmdSSHAgent(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ssh-agent", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // Never reflect flag values or token bytes.
	tokenFile := fs.String("token-file", "", "this agent's token file")
	socket := fs.String("socket", "", "absolute path for the agent socket")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *tokenFile == "" ||
		(*socket != "" && !filepath.IsAbs(*socket)) {
		fmt.Fprintln(stderr, sshAgentUsage)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveSSHAgentSocket(ctx, getenv, *tokenFile, *socket, stdout, stderr)
}

// serveSSHAgentSocket publishes an ssh-agent endpoint for one agent token.
// This process holds no vault state: every frame is answered by the daemon,
// which owns the unlocked session, the grants and the private key. The
// endpoint's custody is the daemon's: a 0700 directory and a 0600 socket this
// uid owns, plus a kernel peer-uid check on every connection.
func serveSSHAgentSocket(ctx context.Context, getenv func(string) string, tokenFile, socket string, stdout, stderr io.Writer) int {
	fail := func(message string) int {
		fmt.Fprintln(stderr, message)
		return 1
	}
	token, err := readAgentToken(tokenFile)
	if err != nil {
		return fail(err.Error())
	}
	defer vault.Wipe(token)
	if socket == "" {
		socket = sshAgentDefaultSocket(getenv)
	}
	// Refuse now rather than at the first git push: without an unlocked
	// daemon this socket can never sign anything.
	probe, err := daemonDial(getenv)
	if err != nil {
		return fail(errDaemonReach.Error())
	}
	probe.Close()
	listener, err := listenUserSocket(socket)
	if err != nil {
		return fail(err.Error())
	}
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	if _, err := fmt.Fprintln(stdout, socket); err != nil {
		return fail("ssh-agent endpoint could not be reported")
	}
	var conns sync.WaitGroup
	for {
		conn, err := listener.Accept()
		if err != nil {
			break
		}
		conns.Add(1)
		go func() {
			defer conns.Done()
			defer conn.Close()
			// An SSH client holds its agent connection open for the whole
			// session, so shutdown closes it rather than waiting for it.
			release := context.AfterFunc(ctx, func() { conn.Close() })
			defer release()
			if err := relaySSHAgent(getenv, conn, token); err != nil && ctx.Err() == nil {
				fmt.Fprintln(stderr, err.Error())
			}
		}()
	}
	conns.Wait()
	return 0
}

// relaySSHAgent gives one SSH client its own authenticated daemon connection,
// so each client gets a fresh conversation with no state from another. The
// protocol bytes are copied, never inspected, rewritten, or logged.
func relaySSHAgent(getenv func(string) string, conn net.Conn, token []byte) error {
	if !daemonPeerAllowed(conn, os.Getuid()) {
		return errSSHAgentRelay // A foreign peer gets no answer and no bytes.
	}
	up, err := daemonDial(getenv)
	if err != nil {
		return errDaemonReach
	}
	defer up.Close()
	hello := daemonHelloLine(daemonVerbSSHAgent, token)
	err = daemonRequest(up, string(hello))
	vault.Wipe(hello)
	if err != nil {
		return errSSHAgentRelay
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(up, conn)
		if half, ok := up.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
	}()
	_, copyErr := io.Copy(conn, up)
	conn.Close()
	<-done
	if copyErr != nil {
		return errSSHAgentRelay
	}
	return nil
}
