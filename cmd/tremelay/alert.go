package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

const (
	// alertQueueMax bounds the alerts one run of the command receives. An
	// alert that finds the queue full is refused, and the vault audits that
	// as a failed delivery.
	alertQueueMax = 100
	// alertMinInterval separates two runs of the command, so a flood of
	// high-risk events reaches the owner as a few batches, not as one
	// process and one message per event.
	alertMinInterval = 30 * time.Second
	// alertCommandTimeout ends a command that hangs.
	alertCommandTimeout = 30 * time.Second
	// alertFinalTimeout bounds the last run while the daemon is exiting.
	alertFinalTimeout = 5 * time.Second
)

var (
	errAlertCommand   = errors.New("--alert-command must be the absolute path of an executable file")
	errAlertQueueFull = errors.New("alert queue full")
	errAlertFailed    = errors.New("alert command failed; the alerts it was given are in the vault audit")
)

// alertSink hands high-risk alerts to the owner's command. The vault calls
// Notify from inside an agent's request, so Notify only queues: the command
// runs on its own goroutine and a slow or hanging one delays nobody.
//
// The command gets one JSON object per line on stdin, each a secret-free
// vault.Notification, and after them {"dropped":N} when alerts were refused
// since the last run. It is executed directly, with no shell and no arguments.
//
// ponytail: the audit row "notify delivered" means the alert entered this
// queue. A command that then fails is reported on the daemon's stderr, not in
// the audit chain. Upgrade path: write the command's outcome back as an audit
// row if owners need it there.
type alertSink struct {
	command  string
	stderr   io.Writer
	interval time.Duration

	mu      sync.Mutex
	queue   []vault.Notification
	dropped int
	wake    chan struct{}
	done    chan struct{}
}

// checkAlertCommand refuses a command the daemon could not run later, before
// a passphrase is asked for.
func checkAlertCommand(path string) error {
	if !filepath.IsAbs(path) {
		return errAlertCommand
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errAlertCommand
	}
	if _, err := exec.LookPath(path); err != nil {
		return errAlertCommand
	}
	return nil
}

func newAlertSink(command string, stderr io.Writer) *alertSink {
	return &alertSink{
		command:  command,
		stderr:   stderr,
		interval: alertMinInterval,
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
}

func (a *alertSink) Notify(n vault.Notification) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.queue) >= alertQueueMax {
		a.dropped++
		return errAlertQueueFull
	}
	a.queue = append(a.queue, n)
	select {
	case a.wake <- struct{}{}:
	default:
	}
	return nil
}

// run delivers batches until ctx ends, then delivers what is left once more.
func (a *alertSink) run(ctx context.Context) {
	defer close(a.done)
	for {
		select {
		case <-a.wake:
		case <-ctx.Done():
			a.flush(alertFinalTimeout)
			return
		}
		a.flush(alertCommandTimeout)
		select {
		case <-time.After(a.interval):
		case <-ctx.Done():
			a.flush(alertFinalTimeout)
			return
		}
	}
}

func (a *alertSink) flush(timeout time.Duration) {
	a.mu.Lock()
	batch, dropped := a.queue, a.dropped
	a.queue, a.dropped = nil, 0
	a.mu.Unlock()
	if len(batch) == 0 && dropped == 0 {
		return
	}
	var input bytes.Buffer
	enc := json.NewEncoder(&input)
	for _, n := range batch {
		_ = enc.Encode(n)
	}
	if dropped > 0 {
		_ = enc.Encode(map[string]int{"dropped": dropped})
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.command)
	cmd.Stdin = &input
	cmd.Env = alertEnv(os.Environ())
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		// Fixed text: the command's own output and error are not echoed.
		fmt.Fprintln(a.stderr, errAlertFailed.Error())
	}
}

// alertEnv is the daemon's environment without the vault passphrase, which a
// daemon started with TREMELAY_PASSPHRASE still carries.
func alertEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, entry := range env {
		// Windows environment names are case-insensitive.
		if !strings.HasPrefix(strings.ToUpper(entry), "TREMELAY_PASSPHRASE=") {
			out = append(out, entry)
		}
	}
	return out
}
