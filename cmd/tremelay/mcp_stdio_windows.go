//go:build windows

package main

import (
	"errors"
	"io"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsPipeInterval = 10 * time.Millisecond

// windowsPipe owns one non-inheritable duplicate. The reservation covers the
// interval BEFORE the syscall starts as well as the syscall itself. A single
// CancelIoEx (including os.File.Close's) can miss that interval on synchronous
// inherited pipes. Close prohibits new reservations, repeatedly cancels, joins
// the last reservation, and only then releases the native handle. There is no
// per-I/O goroutine or request queue. Each direction has one caller at a time.
type windowsPipe struct {
	file                   *os.File
	handle                 windows.Handle
	mu                     sync.Mutex
	busy, closed, released bool
	idle                   chan struct{}
	once                   sync.Once
	err                    error
}

func duplicateWindowsPipe(source *os.File) (*windowsPipe, error) {
	if source == nil {
		return nil, errMCPStdio
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, errMCPStdio
	}
	var h windows.Handle
	var nativeErr error
	err = raw.Control(func(fd uintptr) {
		typ, e := windows.GetFileType(windows.Handle(fd))
		if e != nil || typ != windows.FILE_TYPE_PIPE {
			nativeErr = errMCPStdio
			return
		}
		current := windows.CurrentProcess()
		nativeErr = windows.DuplicateHandle(current, windows.Handle(fd), current, &h, 0, false, windows.DUPLICATE_SAME_ACCESS)
	})
	if err != nil || nativeErr != nil || h == 0 || h == windows.InvalidHandle {
		if h != 0 && h != windows.InvalidHandle {
			windows.CloseHandle(h)
		}
		return nil, errMCPStdio
	}
	f := os.NewFile(uintptr(h), "mcp-owned-pipe")
	if f == nil {
		windows.CloseHandle(h)
		return nil, errMCPStdio
	}
	idle := make(chan struct{})
	close(idle)
	return &windowsPipe{file: f, handle: h, idle: idle}, nil
}

func (p *windowsPipe) begin() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return os.ErrClosed
	}
	if p.busy {
		return errMCPStdio
	}
	p.busy = true
	p.idle = make(chan struct{})
	return nil
}

func (p *windowsPipe) end() {
	p.mu.Lock()
	p.busy = false
	close(p.idle)
	p.mu.Unlock()
}

func (p *windowsPipe) Read(b []byte) (int, error) {
	if err := p.begin(); err != nil {
		return 0, err
	}
	defer p.end()
	return p.file.Read(b)
}

func (p *windowsPipe) Write(b []byte) (int, error) {
	if err := p.begin(); err != nil {
		return 0, err
	}
	defer p.end()
	return p.file.Write(b)
}

func (p *windowsPipe) cancelOutstanding() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.released {
		return nil
	}
	err := windows.CancelIoEx(p.handle, nil)
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return nil // A reserved operation may not have entered the kernel yet.
	}
	return err
}

func (p *windowsPipe) Close() error {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		idle := p.idle
		p.mu.Unlock()
		ticker := time.NewTicker(windowsPipeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-idle:
				p.mu.Lock()
				// No operation can start now, and cancellation calls use this
				// same mutex, so no caller can cancel a recycled handle.
				if p.file.Close() != nil {
					p.err = errMCPStdio
				}
				p.released = true
				p.mu.Unlock()
				return
			default:
			}
			if p.cancelOutstanding() != nil {
				p.err = errMCPStdio
			}
			select {
			case <-idle:
			case <-ticker.C:
			}
		}
	})
	return p.err
}

type mcpStdio struct{ in, out *windowsPipe }

func openMCPStdio(input io.Reader, output io.Writer) (*mcpStdio, error) {
	r, okR := input.(*os.File)
	w, okW := output.(*os.File)
	if !okR || !okW {
		return nil, errMCPStdio
	}
	in, err := duplicateWindowsPipe(r)
	if err != nil {
		return nil, err
	}
	out, err := duplicateWindowsPipe(w)
	if err != nil {
		in.Close()
		return nil, err
	}
	return &mcpStdio{in, out}, nil
}

func (s *mcpStdio) close() { s.in.Close(); s.out.Close() }

// Native metadata buffers must honor their ULONG field alignment. A byte
// array has alignment 1 and can be placed at an unaligned stack address.
// Keep the zero-size alignment marker first so it adds no trailing padding.
type windowsPipeLocalInformation struct {
	_                   [0]uintptr
	pipeType            uint32
	configuration       uint32
	maximumInstances    uint32
	currentInstances    uint32
	inboundQuota        uint32
	readDataAvailable   uint32
	outboundQuota       uint32
	writeQuotaAvailable uint32
	state               uint32
	end                 uint32
}

// Both directions of each subtraction make a changed ABI a compile error.
var (
	_ [40 - unsafe.Sizeof(windowsPipeLocalInformation{})]byte
	_ [unsafe.Sizeof(windowsPipeLocalInformation{}) - 40]byte
	_ [32 - unsafe.Offsetof(windowsPipeLocalInformation{}.state)]byte
	_ [unsafe.Offsetof(windowsPipeLocalInformation{}.state) - 32]byte
	_ [36 - unsafe.Offsetof(windowsPipeLocalInformation{}.end)]byte
	_ [unsafe.Offsetof(windowsPipeLocalInformation{}.end) - 36]byte
	_ [unsafe.Alignof(windowsPipeLocalInformation{}) - unsafe.Alignof(uintptr(0))]byte
)

// FilePipeLocalInformation (24) is ten ULONGs on all Windows architectures.
// Unlike GetNamedPipeHandleState's read/wait modes this reports connection
// state, including a closed peer with unread bytes. A query consumes no data.
// NtQueryInformationFile is a synchronous API even for overlapped handles:
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ioisoperationsynchronous
// The reservation covers the syscall, including its kernel completion wait.
// There is no separate file-event wait whose notification an inherited
// FILE_SKIP_SET_EVENT_ON_HANDLE could suppress.
func (p *windowsPipe) connected() (bool, error) {
	if err := p.begin(); err != nil {
		return false, err
	}
	defer p.end()
	var info windowsPipeLocalInformation
	iosb := windows.IO_STATUS_BLOCK{Status: windows.STATUS_PENDING}
	err := windows.NtQueryInformationFile(p.handle, &iosb, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), 24)
	if err != nil {
		return false, err
	}
	if iosb.Status != 0 || iosb.Information != unsafe.Sizeof(info) ||
		info.pipeType != windows.FILE_PIPE_BYTE_STREAM_TYPE ||
		info.configuration > windows.FILE_PIPE_FULL_DUPLEX ||
		info.end > windows.FILE_PIPE_SERVER_END {
		return false, errMCPStdio
	}
	switch info.state {
	case windows.FILE_PIPE_CONNECTED_STATE:
		return true, nil
	case windows.FILE_PIPE_DISCONNECTED_STATE, windows.FILE_PIPE_LISTENING_STATE, windows.FILE_PIPE_CLOSING_STATE:
		return false, nil
	default:
		return false, errMCPStdio
	}
}

func (s *mcpStdio) watchDisconnect(cancel func()) func() {
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		verified := false
		defer func() {
			if !verified {
				cancel()
			}
		}()
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			select {
			case <-stop:
				return
			case <-timer.C:
			}
			connected, err := s.in.connected()
			if connected && err == nil {
				connected, err = s.out.connected()
			}
			if !connected {
				if verified && errors.Is(err, windows.STATUS_CANCELLED) {
					select {
					case <-stop:
						// Only cancellation caused by Stop can be ignored,
						// never an observed disconnect or failed query.
						return
					default:
					}
				}
				cancel()
				return
			}
			verified = true
			timer.Reset(50 * time.Millisecond)
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(stop)
			ticker := time.NewTicker(windowsPipeInterval)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				default:
				}
				_ = s.in.cancelOutstanding()
				_ = s.out.cancelOutstanding()
				select {
				case <-done:
					return
				case <-ticker.C:
				}
			}
		})
	}
}
