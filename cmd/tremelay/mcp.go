package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

const mcpServeUsage = "usage: tremelay mcp --daemon --token-file PATH\n   or: tremelay mcp serve --path PATH --agent ID --pinentry /absolute/helper [--pinentry-tty /absolute/tty] [--unlock-timeout 2m]"

var errMCPStdio = errors.New("mcp serve requires supported, close-interruptible stdin and stdout pipes")

func cmdMCP(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, mcpServeUsage)
		return 2
	}
	if args[0] != "serve" {
		return cmdMCPDaemon(args, getenv, stdin, stdout, stderr)
	}
	fs := flag.NewFlagSet("mcp serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // Never reflect flag values or helper diagnostics.
	path := fs.String("path", "", "vault file")
	agentID := fs.String("agent", "", "host-selected agent id")
	helper := fs.String("pinentry", "", "absolute trusted pinentry executable")
	tty := fs.String("pinentry-tty", "", "absolute host-selected terminal")
	timeout := fs.Duration("unlock-timeout", 2*time.Minute, "interactive unlock timeout (1s through 5m)")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *path == "" || *agentID == "" ||
		!filepath.IsAbs(*helper) || (*tty != "" && !validPinentryTTY(*tty)) || *timeout < time.Second || *timeout > 5*time.Minute {
		fmt.Fprintln(stderr, mcpServeUsage)
		return 2
	}
	stopPipe := lifecyclePipeErrors()
	defer stopPipe()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveMCP(ctx, *path, *agentID, pinentryOptions{path: *helper, tty: *tty}, *timeout, stdin, stdout, stderr)
}

// cmdMCPDaemon is the default agent path: an already-unlocked daemon holds the
// vault, and this process only authenticates and relays. Pinentry stays
// available as `tremelay mcp serve`, the non-default option.
func cmdMCPDaemon(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // Never reflect flag values or token bytes.
	useDaemon := fs.Bool("daemon", false, "connect to the running tremelay daemon")
	tokenFile := fs.String("token-file", "", "this agent's token file")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || !*useDaemon || *tokenFile == "" {
		fmt.Fprintln(stderr, mcpServeUsage)
		return 2
	}
	stopPipe := lifecyclePipeErrors()
	defer stopPipe()
	return relayDaemonMCP(getenv, *tokenFile, stdin, stdout, stderr)
}

func serveMCP(ctx context.Context, path, agentID string, options pinentryOptions, timeout time.Duration, stdin io.Reader, stdout, stderr io.Writer) int {
	fail := func(message string) int {
		fmt.Fprintln(stderr, message)
		return 1
	}
	stream, err := openMCPStdio(stdin, stdout)
	if err != nil {
		return fail(errMCPStdio.Error())
	}
	defer stream.close()
	unlockCtx, cancelUnlock := context.WithTimeout(ctx, timeout)
	defer cancelUnlock()
	// A client that leaves during the prompt must not leave a helper waiting.
	// Polling observes pipe closure without reading any MCP request bytes.
	stopWatch := stream.watchDisconnect(cancelUnlock)
	pass, err := readPinentry(unlockCtx, options)
	stopWatch()
	// Joining the watcher can expose cancellation just after the helper
	// returned. Do not unlock with a late successful answer, and do not
	// replace a terminal-restoration failure or timeout with cancellation.
	err = pinentryDiagnostic(unlockCtx, err, nil)
	if err != nil {
		vault.Wipe(pass)
		return fail(err.Error()) // readPinentry returns only fixed local errors.
	}
	// Unlock has no context API. Finish its bounded KDF, wipe immediately, and
	// refuse service if the prompt deadline or process cancellation has passed.
	// No logger/redactor is needed: passphrase bytes never become diagnostics.
	session, err := vault.Unlock(path, pass, nil)
	vault.Wipe(pass)
	if err != nil {
		return fail("vault unlock failed")
	}
	defer session.Lock() // Serve has joined dispatch and output before this runs.
	failUnlocked := func(message string) int {
		// A host stderr pipe can also be blocked. Release custody before
		// writing any diagnostic, rather than depending on deferred cleanup.
		session.Lock()
		return fail(message)
	}
	if unlockCtx.Err() != nil {
		return failUnlocked(pinentryContextError(unlockCtx).Error())
	}
	cancelUnlock()
	principal, err := session.Agent(agentID)
	if err != nil {
		return failUnlocked("mcp agent binding failed")
	}
	capability, err := vault.BindAgentCapability(principal)
	if err != nil {
		return failUnlocked("mcp agent binding failed")
	}
	endpoint, err := vault.BindStdioMCPEndpoint(capability)
	if err != nil {
		return failUnlocked("mcp agent binding failed")
	}
	err = endpoint.Serve(ctx, stream.in, stream.out)
	session.Lock()
	if err != nil {
		// Required audit failure must not be mistaken for ordinary cancellation.
		if errors.Is(err, context.Canceled) {
			return fail("mcp session cancelled")
		}
		return fail("mcp session failed; inspect the vault audit before retrying an operation")
	}
	return 0
}
