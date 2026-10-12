package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CharitonMedia/Tremelay/internal/vault"
)

const maxPinentryPassphrase = 1024
const maxPinentryLine = 3*maxPinentryPassphrase + 4 // D prefix, CR and LF
const maxPinentryReply = 16 * 1024

var (
	errPinentryUnavailable = errors.New("pinentry unavailable; a trusted executable and interactive terminal or display are required")
	errPinentryFailed      = errors.New("pinentry failed; check the selected terminal or display")
	errPinentryCancelled   = errors.New("pinentry cancelled")
	errPinentryTimeout     = errors.New("pinentry unlock timed out")
	errPinentryTerminal    = errors.New("pinentry terminal restoration failed")
)

type pinentryOptions struct{ path, tty string }

func validPinentryTTY(path string) bool {
	if !filepath.IsAbs(path) || len(path) > 1024 {
		return false
	}
	for _, ch := range path {
		if ch < 33 || ch > 126 || ch == '%' {
			return false
		}
	}
	return true
}

func pinentryContextError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errPinentryTimeout
	}
	return errPinentryCancelled
}

// readPinentry never uses the MCP streams, an environment passphrase, a shell,
// or caller-controlled prompt text. The selected executable and its UI stack
// are trusted host custody. Every pipe, helper process and terminal lease is
// closed before return, including cancellation and malformed helper output.
func readPinentry(ctx context.Context, options pinentryOptions) (pass []byte, err error) {
	if ctx.Err() != nil {
		return nil, pinentryContextError(ctx)
	}
	if !filepath.IsAbs(options.path) {
		return nil, errPinentryUnavailable
	}
	info, e := os.Stat(options.path)
	if e != nil || !info.Mode().IsRegular() {
		return nil, errPinentryUnavailable
	}
	restore, tty, e := pinentryTerminal(options.tty)
	if e != nil {
		return nil, errPinentryUnavailable
	}
	defer func() {
		if e := restore(); e != nil {
			err = errPinentryTerminal
		}
		if err != nil {
			vault.Wipe(pass)
			pass = nil
		}
	}()
	toHelper, input, e := os.Pipe()
	if e != nil {
		return nil, errPinentryUnavailable
	}
	defer toHelper.Close()
	defer input.Close()
	output, fromHelper, e := os.Pipe()
	if e != nil {
		return nil, errPinentryUnavailable
	}
	defer output.Close()
	defer fromHelper.Close()
	devnull, e := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if e != nil {
		return nil, errPinentryUnavailable
	}
	defer devnull.Close()
	cmd := exec.Command(options.path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = toHelper, fromHelper, devnull
	// UI discovery only. In particular, no TREMELAY_PASSPHRASE or arbitrary
	// agent/host environment is inherited by the helper.
	cmd.Env = []string{}
	for _, key := range []string{"HOME", "TERM", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "LANG", "LC_CTYPE", "LC_MESSAGES"} {
		if value, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	if e := cmd.Start(); e != nil {
		return nil, errPinentryUnavailable
	}
	toHelper.Close()
	fromHelper.Close()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	finished := false
	afterDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(afterDone)
		input.Close()
		output.Close()
		_ = cmd.Process.Kill()
	})
	defer func() {
		if !stop() {
			<-afterDone
		}
		input.Close()
		output.Close()
		if !finished {
			_ = cmd.Process.Kill()
			<-waited
		}
		if ctx.Err() != nil {
			err = pinentryContextError(ctx)
		}
	}()
	protocol := pinentryProtocol{reader: output, writer: input}
	if _, e := protocol.reply(false); e != nil {
		return nil, e
	}
	commands := []string{"SETTITLE Tremelay", "SETDESC Unlock the local vault for this MCP session.", "SETPROMPT Vault passphrase:"}
	if tty != "" {
		commands = append([]string{"OPTION ttyname=" + tty}, commands...)
	}
	for _, command := range commands {
		if e := protocol.command(command); e != nil {
			return nil, e
		}
		if _, e := protocol.reply(false); e != nil {
			return nil, e
		}
	}
	if e := protocol.command("GETPIN"); e != nil {
		return nil, e
	}
	pass, err = protocol.reply(true)
	if err != nil {
		return pass, err
	}
	if e := protocol.command("BYE"); e != nil {
		return pass, e
	}
	input.Close()
	// Normal helpers exit after BYE. A helper that hangs after returning data
	// must not retain the passphrase or delay cleanup for the whole UI timeout.
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case e := <-waited:
		finished = true
		if e != nil {
			return pass, errPinentryFailed
		}
	case <-ctx.Done():
		return pass, pinentryContextError(ctx)
	case <-timer.C:
		return pass, errPinentryFailed
	}
	return pass, nil
}

type pinentryProtocol struct {
	reader io.Reader
	writer io.Writer
}

func (p *pinentryProtocol) command(command string) error {
	if n, err := io.WriteString(p.writer, command+"\n"); err != nil || n != len(command)+1 {
		return errPinentryFailed
	}
	return nil
}

// Fixed storage avoids scanner/reader growth and hidden passphrase copies.
// Assuan may split escaped data across D lines. Both wire bytes and decoded
// bytes have independent bounds; all reply text is discarded, never logged.
func (p *pinentryProtocol) reply(data bool) (pass []byte, err error) {
	var line [maxPinentryLine]byte
	defer vault.Wipe(line[:])
	if data {
		pass = make([]byte, 0, maxPinentryPassphrase)
	}
	defer func() {
		if err != nil {
			vault.Wipe(pass[:cap(pass)])
			pass = nil
		}
	}()
	total := 0
	for count := 0; count < 64; count++ {
		n := 0
		for {
			if n == len(line) || total == maxPinentryReply {
				return pass, errPinentryFailed
			}
			if _, e := io.ReadFull(p.reader, line[n:n+1]); e != nil {
				return pass, errPinentryFailed
			}
			total++
			if line[n] == '\n' {
				break
			}
			n++
		}
		value := line[:n]
		if n > 0 && value[n-1] == '\r' {
			value = value[:n-1]
		}
		switch {
		case bytes.Equal(value, []byte("OK")) || bytes.HasPrefix(value, []byte("OK ")):
			return pass, nil
		case bytes.HasPrefix(value, []byte("ERR ")):
			return pass, pinentryReplyError(value[4:])
		case bytes.HasPrefix(value, []byte("S ")) || bytes.HasPrefix(value, []byte("#")):
			// Status/comment lines are bounded and discarded, not reflected.
		case data && bytes.HasPrefix(value, []byte("D ")):
			for i := 2; i < len(value); i++ {
				ch := value[i]
				if ch == '%' {
					if i+2 >= len(value) {
						return pass, errPinentryFailed
					}
					hi, lo := pinentryHex(value[i+1]), pinentryHex(value[i+2])
					if hi < 0 || lo < 0 {
						return pass, errPinentryFailed
					}
					ch, i = byte(hi<<4|lo), i+2
				}
				if len(pass) == maxPinentryPassphrase {
					return pass, errPinentryFailed
				}
				pass = append(pass, ch)
			}
		default:
			return pass, errPinentryFailed
		}
		vault.Wipe(line[:])
	}
	return pass, errPinentryFailed
}

func pinentryHex(ch byte) int {
	switch {
	case ch >= '0' && ch <= '9':
		return int(ch - '0')
	case ch >= 'a' && ch <= 'f':
		return int(ch-'a') + 10
	case ch >= 'A' && ch <= 'F':
		return int(ch-'A') + 10
	}
	return -1
}

func pinentryReplyError(value []byte) error {
	i := bytes.IndexByte(value, ' ')
	if i < 0 {
		i = len(value)
	}
	if i > 10 || i == 0 || strings.IndexFunc(string(value[:i]), func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return errPinentryFailed
	}
	code, err := strconv.ParseUint(string(value[:i]), 10, 32)
	if err != nil {
		return errPinentryFailed
	}
	switch code & 0xffff { // libgpg-error source bits do not change the code.
	case 99, 198:
		return errPinentryCancelled
	case 62:
		return errPinentryTimeout
	}
	return errPinentryFailed
}
