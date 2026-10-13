//go:build linux || darwin

package main

import (
	"io"
	"os"
	"sync"
	"time"

	"github.com/CharitonMedia/Tremelay/internal/mcpstdio"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

type mcpStdio struct {
	in, out     *os.File
	inFD, outFD int
}

// Inherited os.Stdin/os.Stdout may be blocking, unpollable Go files. Duplicate
// first, enable O_NONBLOCK, then construct Go files that register with netpoll.
// Their Close interrupts blocked reads AND writes, as MCPEndpoint requires.
// Only inherited pipes or connected unnamed Unix stream pairs are supported.
func openMCPStdio(input io.Reader, output io.Writer) (*mcpStdio, error) {
	r, okR := input.(*os.File)
	w, okW := output.(*os.File)
	if !okR || !okW {
		return nil, errMCPStdio
	}
	in, inFD, err := duplicateMCPStream(r)
	if err != nil {
		return nil, err
	}
	out, outFD, err := duplicateMCPStream(w)
	if err != nil {
		in.Close()
		return nil, err
	}
	if in.SetReadDeadline(time.Time{}) != nil || out.SetWriteDeadline(time.Time{}) != nil {
		in.Close()
		out.Close()
		return nil, errMCPStdio
	}
	return &mcpStdio{in: in, out: out, inFD: inFD, outFD: outFD}, nil
}

func duplicateMCPStream(source *os.File) (*os.File, int, error) {
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, 0, errMCPStdio
	}
	fd := -1
	var dupErr error
	err = raw.Control(func(sourceFD uintptr) {
		fd, dupErr = unix.FcntlInt(sourceFD, unix.F_DUPFD_CLOEXEC, 3)
	})
	if err != nil || dupErr != nil || fd < 0 {
		return nil, 0, errMCPStdio
	}
	if !mcpstdio.ValidInheritedStream(fd) {
		unix.Close(fd)
		return nil, 0, errMCPStdio
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, 0, errMCPStdio
	}
	return os.NewFile(uintptr(fd), "mcp-pipe"), fd, nil
}

func (s *mcpStdio) close() { s.in.Close(); s.out.Close() }

func (s *mcpStdio) watchDisconnect(cancel func()) func() {
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		// Darwin needs an interested read/write filter to report pipe EOF.
		// Readiness itself is not a disconnect and must not consume MCP bytes.
		fds := []unix.PollFd{
			{Fd: int32(s.inFD), Events: unix.POLLIN | mcpstdio.ReadHalfClosed},
			{Fd: int32(s.outFD), Events: unix.POLLOUT},
		}
		pause := time.NewTimer(50 * time.Millisecond)
		pause.Stop()
		defer pause.Stop()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, err := unix.Poll(fds, 0)
			if err != nil {
				if err != unix.EINTR {
					cancel()
					return
				}
			} else {
				// An interrupted poll need not refresh revents; inspect them
				// only after a successful snapshot.
				for _, fd := range fds {
					if fd.Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL|mcpstdio.ReadHalfClosed) != 0 {
						cancel()
						return
					}
				}
			}
			// Writable stdout and buffered stdin are commonly always ready.
			// Pace every nonterminal snapshot, including EINTR, with a full
			// interruptible interval rather than spinning on that readiness.
			pause.Reset(50 * time.Millisecond)
			select {
			case <-stop:
				return
			case <-pause.C:
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(stop); <-done }) }
}

// Keep a separately opened terminal state until AFTER the helper is reaped.
// Even a killed curses helper cannot leave ECHO disabled on cancellation.
// No terminal bytes pass through the MCP pipes. Without a controlling terminal,
// a GUI helper may use its trusted display; curses will fail with a fixed error.
func pinentryTerminal(selected string) (func() error, string, error) {
	tty := selected
	if tty == "" {
		tty = "/dev/tty"
	}
	if !validPinentryTTY(tty) {
		return nil, "", errPinentryUnavailable
	}
	fd, err := unix.Open(tty, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if selected == "" {
			return func() error { return nil }, "", nil
		}
		return nil, "", errPinentryUnavailable
	}
	state, err := term.GetState(fd)
	if err != nil {
		unix.Close(fd)
		return nil, "", errPinentryUnavailable
	}
	return func() error {
		err := term.Restore(fd, state)
		unix.Close(fd)
		return err
	}, tty, nil
}
