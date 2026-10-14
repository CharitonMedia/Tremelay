package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

const (
	daemonUsage = "usage: tremelay daemon --vault PATH [--idle-timeout 1h]"
	lockUsage   = "usage: tremelay lock"

	// The handshake is one bounded line. Its only verbs are agent token
	// authentication, the same authentication for one ssh-agent conversation,
	// and the owner's lock-and-exit request. There is no human control-plane
	// operation and no raw-secret retrieval path on this wire.
	daemonHello        = "TREMELAY/1 "
	daemonVerbAuth     = "AUTH "
	daemonVerbSSHAgent = "SSHAGENT "
	daemonVerbLock     = "LOCK"
	daemonOK           = "OK\n"
	daemonErr          = "ERR\n"
	maxDaemonHello     = 96
	maxDaemonAnswer    = 8
	daemonHelloWait    = 10 * time.Second

	minIdleTimeout = time.Second
	maxIdleTimeout = 24 * time.Hour
)

var (
	errDaemonEndpoint = errors.New("daemon endpoint must be a user-only directory and socket this user owns")
	errDaemonRunning  = errors.New("a daemon is already serving this endpoint")
	errDaemonReach    = errors.New("no unlocked daemon is reachable")
	errDaemonRefused  = errors.New("daemon refused the agent token")
	errDaemonSession  = errors.New("daemon agent session failed; inspect the vault audit before retrying an operation")
	errDaemonTerminal = errors.New("daemon can no longer serve this vault and has locked; inspect the vault audit, then restart it")
	errAgentToken     = errors.New("agent token file must be a regular user-only file holding one hex token")
)

func cmdDaemon(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // Never reflect flag values into diagnostics.
	path := fs.String("vault", "", "vault file")
	idle := fs.Duration("idle-timeout", time.Hour, "lock and exit after this much idle time")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *path == "" ||
		*idle < minIdleTimeout || *idle > maxIdleTimeout {
		fmt.Fprintln(stderr, daemonUsage)
		return 2
	}
	stopPipe := lifecyclePipeErrors()
	defer stopPipe()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveDaemon(ctx, *path, *idle, getenv, stdin, stdout, stderr)
}

// serveDaemon unlocks once from the human's terminal and then holds that
// Session in memory only. Nothing writes the passphrase or the unlocked state
// to disk, so losing the process (including a reboot) locks the vault.
func serveDaemon(ctx context.Context, path string, idle time.Duration, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fail := func(message string) int {
		fmt.Fprintln(stderr, message)
		return 1
	}
	// A refused endpoint must be known before a passphrase is requested.
	listener, endpoint, err := daemonListen(getenv)
	if err != nil {
		return fail(err.Error())
	}
	defer listener.Close()
	pass, err := readPassphrase(getenv, stdin, stderr)
	if err != nil {
		return fail(err.Error())
	}
	// No logger: passphrase bytes must not become a retained redactor copy,
	// and this process outlives every other CLI command.
	session, err := vault.Unlock(path, pass, nil)
	vault.Wipe(pass)
	if err != nil {
		return fail("vault unlock failed")
	}
	connCtx, cancelConns := context.WithCancel(ctx)
	d := &daemon{
		session: session,
		stderr:  stderr,
		ctx:     connCtx,
		idle:    idle,
		timer:   time.NewTimer(idle),
		locked:  make(chan struct{}),
	}
	defer d.timer.Stop()
	go d.accept(listener)
	if _, err := fmt.Fprintln(stdout, endpoint); err != nil {
		cancelConns()
		listener.Close()
		d.conns.Wait()
		session.Lock()
		return fail("daemon endpoint could not be reported")
	}
	select {
	case <-ctx.Done():
	case <-d.locked:
	case <-d.timer.C:
	}
	// Stop new work, interrupt every served connection, join dispatch and
	// output, and only then zeroise. A client call after this fails closed.
	cancelConns()
	listener.Close()
	d.conns.Wait()
	session.Lock()
	return 0
}

// daemon serves one unlocked Session to many agents. Every vault entry point
// serializes on that session; the daemon itself calls only the public
// authentication and lock operations. Production configures no vault callback.
type daemon struct {
	session *vault.Session
	stderr  io.Writer
	ctx     context.Context
	idle    time.Duration
	timer   *time.Timer
	locked  chan struct{}
	once    sync.Once
	conns   sync.WaitGroup

	mu   sync.Mutex
	live int
}

func (d *daemon) accept(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		d.enter()
		d.conns.Add(1)
		go func() {
			defer d.conns.Done()
			defer d.leave()
			d.handle(conn)
		}()
	}
}

// enter and leave keep the idle deadline running only while no agent is
// connected. A connection arriving exactly at expiry may still lose the race
// and find a locked session, which is the fail-closed direction.
func (d *daemon) enter() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.live++
	if d.live == 1 {
		d.timer.Stop()
	}
}

func (d *daemon) leave() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.live--
	if d.live == 0 {
		d.timer.Reset(d.idle)
	}
}

func (d *daemon) requestLock() {
	d.once.Do(func() { close(d.locked) })
}

// handle answers one connection. The agent principal is derived only from the
// token. No frame, argument, or caller-supplied identifier can select it.
func (d *daemon) handle(conn net.Conn) {
	defer conn.Close()
	if !daemonPeerAllowed(conn) {
		return // A foreign peer gets no answer and no audit attribution.
	}
	if conn.SetDeadline(time.Now().Add(daemonHelloWait)) != nil {
		return
	}
	verb, token, err := readDaemonHello(conn)
	defer vault.Wipe(token)
	if err != nil {
		_, _ = io.WriteString(conn, daemonErr)
		return
	}
	if verb == daemonVerbLock {
		// The owner's uid is the only authority this verb needs: it destroys
		// authority and can neither read nor change vault state.
		_, _ = io.WriteString(conn, daemonOK)
		d.requestLock()
		return
	}
	principal, err := d.session.AuthenticateAgentToken(token)
	vault.Wipe(token)
	if err != nil {
		// Accepted, wrong-token, and inactive-agent attempts are all audited
		// inside the session. Only an unusable session needs a diagnostic.
		d.checkTerminal(err)
		_, _ = io.WriteString(conn, daemonErr)
		return
	}
	if verb == daemonVerbSSHAgent {
		d.serveSSHAgent(conn, principal)
		return
	}
	capability, err := vault.BindAgentCapability(principal)
	if err != nil {
		_, _ = io.WriteString(conn, daemonErr)
		return
	}
	endpoint, err := vault.BindStdioMCPEndpoint(capability)
	if err != nil {
		_, _ = io.WriteString(conn, daemonErr)
		return
	}
	if _, err := io.WriteString(conn, daemonOK); err != nil {
		return
	}
	// The handshake deadline must not expire under a long-lived MCP session.
	if conn.SetDeadline(time.Time{}) != nil {
		return
	}
	if err := endpoint.Serve(d.ctx, conn, conn); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(d.stderr, errDaemonSession.Error())
		d.checkTerminal(err)
	}
}

// serveSSHAgent answers ssh-agent protocol frames for the authenticated
// principal's own ssh_userauth grants. The vault, the private key and every
// grant check stay in this process; the relay that forwarded these bytes
// holds nothing. Serve has no context, so shutdown closes the connection and
// then waits for it, which is the ordering the SSH stream requires before a
// lock.
func (d *daemon) serveSSHAgent(conn net.Conn, principal *vault.AgentPrincipal) {
	agent, err := principal.SSHAgent()
	if err != nil {
		d.checkTerminal(err)
		_, _ = io.WriteString(conn, daemonErr)
		return
	}
	defer agent.Close()
	if _, err := io.WriteString(conn, daemonOK); err != nil {
		return
	}
	if conn.SetDeadline(time.Time{}) != nil {
		return
	}
	stop := context.AfterFunc(d.ctx, func() { conn.Close() })
	defer stop()
	if err := agent.Serve(conn); err != nil && d.ctx.Err() == nil {
		fmt.Fprintln(d.stderr, errDaemonSession.Error())
		d.checkTerminal(err)
	}
}

// checkTerminal locks and exits when this session can never serve again. A
// human control-plane command run against the same vault advances the durable
// audit sequence, which makes the daemon's cached session stale: it then
// refuses every operation. Holding an unusable DEK serves nobody, so the
// daemon zeroises it and says so instead of refusing calls indefinitely.
func (d *daemon) checkTerminal(err error) {
	if errors.Is(err, vault.ErrStale) || errors.Is(err, vault.ErrCorrupt) || errors.Is(err, vault.ErrAudit) {
		fmt.Fprintln(d.stderr, errDaemonTerminal.Error())
		d.requestLock()
	}
}

// readDaemonHello reads exactly one bounded handshake line. It never buffers
// past the delimiter, so the MCP stream that follows stays intact.
func readDaemonHello(conn net.Conn) (string, []byte, error) {
	line, err := readDaemonLine(conn, maxDaemonHello)
	if err != nil {
		return "", nil, err
	}
	rest, ok := strings.CutPrefix(line, daemonHello)
	if !ok {
		return "", nil, errDaemonRefused
	}
	if rest == daemonVerbLock {
		return daemonVerbLock, nil, nil
	}
	for _, verb := range []string{daemonVerbAuth, daemonVerbSSHAgent} {
		encoded, ok := strings.CutPrefix(rest, verb)
		if !ok || len(encoded) != hex.EncodedLen(vault.AgentTokenLen) {
			continue
		}
		token, err := hex.DecodeString(encoded)
		if err != nil {
			return "", nil, errDaemonRefused
		}
		return verb, token, nil
	}
	return "", nil, errDaemonRefused
}

// daemonHelloLine is the one bounded handshake line a client sends. The token
// is hex only so the line stays delimiter-safe; it is never logged or printed.
func daemonHelloLine(verb string, token []byte) []byte {
	line := make([]byte, 0, len(daemonHello)+len(verb)+hex.EncodedLen(len(token))+1)
	line = append(line, daemonHello+verb...)
	line = hex.AppendEncode(line, token)
	return append(line, '\n')
}

func readDaemonLine(conn net.Conn, limit int) (string, error) {
	buf := make([]byte, 0, limit)
	var one [1]byte
	for len(buf) < limit {
		if _, err := io.ReadFull(conn, one[:]); err != nil {
			return "", errDaemonRefused
		}
		if one[0] == '\n' {
			return string(buf), nil
		}
		buf = append(buf, one[0])
	}
	return "", errDaemonRefused
}

func cmdLock(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lock", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(stderr, lockUsage)
		return 2
	}
	conn, err := daemonDial(getenv)
	if err != nil {
		fmt.Fprintln(stderr, errDaemonReach.Error())
		return 1
	}
	defer conn.Close()
	if err := daemonRequest(conn, daemonHello+daemonVerbLock+"\n"); err != nil {
		fmt.Fprintln(stderr, errDaemonReach.Error())
		return 1
	}
	if _, err := fmt.Fprintln(stdout, "locked"); err != nil {
		fmt.Fprintln(stderr, "lock requested but confirmation output failed")
		return 1
	}
	return 0
}

// relayDaemonMCP is the stdio command an MCP client launches. It authenticates
// with the agent's own token and then relays protocol bytes; it holds no vault
// state, derives no identity, and cannot name an agent.
func relayDaemonMCP(getenv func(string) string, tokenFile string, stdin io.Reader, stdout, stderr io.Writer) int {
	token, err := readAgentToken(tokenFile)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	defer vault.Wipe(token)
	conn, err := daemonDial(getenv)
	if err != nil {
		fmt.Fprintln(stderr, errDaemonReach.Error())
		return 1
	}
	defer conn.Close()
	hello := daemonHelloLine(daemonVerbAuth, token)
	err = daemonRequest(conn, string(hello))
	vault.Wipe(hello)
	vault.Wipe(token)
	if err != nil {
		fmt.Fprintln(stderr, errDaemonRefused.Error())
		return 1
	}
	// Protocol bytes only. Nothing here inspects, logs, or rewrites them.
	done := make(chan struct{})
	var ended atomic.Bool
	go func() {
		defer close(done)
		_, _ = io.Copy(conn, stdin)
		if half, ok := conn.(interface{ CloseWrite() error }); ok && half.CloseWrite() == nil {
			return
		}
		// A named pipe has no half-close. The client's stdin ending ends the
		// session, so the whole connection goes and the read below stops.
		ended.Store(true)
		conn.Close()
	}()
	_, copyErr := io.Copy(stdout, conn)
	conn.Close()
	<-done
	if copyErr != nil && !ended.Load() {
		fmt.Fprintln(stderr, errDaemonReach.Error())
		return 1
	}
	return 0
}

// daemonRequest writes one handshake line and requires the fixed acceptance.
// A refusal carries no detail: the daemon's audit chain holds the reason.
func daemonRequest(conn net.Conn, line string) error {
	if conn.SetDeadline(time.Now().Add(daemonHelloWait)) != nil {
		return errDaemonRefused
	}
	if _, err := io.WriteString(conn, line); err != nil {
		return errDaemonRefused
	}
	answer, err := readDaemonLine(conn, maxDaemonAnswer)
	if err != nil || answer+"\n" != daemonOK {
		return errDaemonRefused
	}
	return conn.SetDeadline(time.Time{})
}

// readAgentToken reads one user-only token file. A file any other principal
// can read is refused rather than used.
func readAgentToken(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errAgentToken
	}
	if err := userOnlyFile(path); err != nil {
		return nil, errAgentToken
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errAgentToken
	}
	defer f.Close()
	limit := hex.EncodedLen(vault.AgentTokenLen) + 2
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)))
	defer vault.Wipe(raw)
	if err != nil {
		return nil, errAgentToken
	}
	encoded := string(raw)
	for len(encoded) > 0 && (encoded[len(encoded)-1] == '\n' || encoded[len(encoded)-1] == '\r') {
		encoded = encoded[:len(encoded)-1]
	}
	if len(encoded) != hex.EncodedLen(vault.AgentTokenLen) {
		return nil, errAgentToken
	}
	token, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, errAgentToken
	}
	return token, nil
}

// writeAgentToken stores one new user-only token and refuses to replace a
// file that already exists. The token is never printed.
func writeAgentToken(path string, token []byte) error {
	f, err := createUserOnlyFile(path)
	if err != nil {
		return errAgentToken
	}
	encoded := hex.AppendEncode(make([]byte, 0, hex.EncodedLen(len(token))+1), token)
	encoded = append(encoded, '\n')
	defer vault.Wipe(encoded)
	_, err = f.Write(encoded)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
		return errAgentToken
	}
	return nil
}
