//go:build windows

package main

import (
	"errors"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// The endpoint is a named pipe whose name carries the owner's SID, so two
	// users on one machine never contend for it, and an optional instance
	// label keeps independent daemons apart. Neither part can widen the
	// boundary: the server creates the first instance with an owner-only
	// descriptor, and a client checks the pipe's owner before it sends a byte.
	daemonPipePrefix   = `\\.\pipe\tremelay-`
	daemonInstanceEnv  = "TREMELAY_DAEMON_INSTANCE"
	maxInstanceLabel   = 64
	pipeBuffer         = 4096
	pipeCancelInterval = 10 * time.Millisecond
	pipeBusyInterval   = 20 * time.Millisecond
	pipeBusyAttempts   = 50

	// A descriptor this program wrote holds one entry. The bound only stops an
	// unbounded walk of a descriptor some other writer produced.
	maxDescriptorACEs = 64

	// GENERIC_READ|GENERIC_WRITE lets the owner open the pipe and create the
	// further instances the accept loop needs (FILE_CREATE_PIPE_INSTANCE is
	// part of the generic write mapping). Nothing else is granted.
	pipeRights = "GRGW"
	// A token file must also be deletable and re-securable by its owner.
	fileRights = "GA"
)

// currentUserSID returns this process's token user: the whole identity
// boundary on Windows. The pipe descriptor names it, every client checks it,
// and every accepted connection must match it.
func currentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid.Copy() // The native buffer is not retained.
}

// userOnlyDescriptor grants the named rights to this user and to nobody else,
// in a protected DACL that inherits nothing, owned by the same SID. Everyone,
// Authenticated Users, Administrators and SYSTEM appear nowhere; only this
// user's own SID can match the one entry. Windows parses the descriptor, so
// no ACL layout is invented here.
func userOnlyDescriptor(rights string) (*windows.SECURITY_DESCRIPTOR, error) {
	sid, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	self := sid.String()
	return windows.SecurityDescriptorFromString("O:" + self + "G:" + self + "D:P(A;;" + rights + ";;;" + self + ")")
}

// descriptorIsUserOnly requires this user to own the object and every DACL
// entry to name this user. A missing DACL, a NULL DACL (which grants
// everyone), or any entry for another principal is refused.
func descriptorIsUserOnly(sd *windows.SECURITY_DESCRIPTOR, self *windows.SID) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(self) {
		return errDaemonEndpoint
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 || dacl.AceCount > maxDescriptorACEs {
		return errDaemonEndpoint
	}
	for index := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return errDaemonEndpoint
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || !sid.Equals(self) {
			return errDaemonEndpoint
		}
	}
	return nil
}

// daemonEndpoint is the pipe name both ends derive. An unusable identity or a
// label that is not plainly safe yields no name, and listen and dial refuse it.
func daemonEndpoint(getenv func(string) string) string {
	sid, err := currentUserSID()
	if err != nil {
		return ""
	}
	name := daemonPipePrefix + sid.String()
	if getenv == nil {
		return name
	}
	label := getenv(daemonInstanceEnv)
	if label == "" {
		return name
	}
	if len(label) > maxInstanceLabel {
		return ""
	}
	for _, c := range []byte(label) {
		safe := c == '-' || c == '_' || ('0' <= c && c <= '9') ||
			('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
		if !safe {
			return ""
		}
	}
	return name + "-" + label
}

func daemonListen(getenv func(string) string) (net.Listener, string, error) {
	name := daemonEndpoint(getenv)
	sd, err := userOnlyDescriptor(pipeRights)
	if name == "" || err != nil {
		return nil, "", errDaemonEndpoint
	}
	handle, err := createPipeInstance(name, sd, true)
	if err != nil {
		// FILE_FLAG_FIRST_PIPE_INSTANCE refuses a name that already has one.
		// Whether that is a live daemon or a squatter who got there first,
		// this process must not serve on it.
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, "", errDaemonRunning
		}
		return nil, "", errDaemonEndpoint
	}
	idle := make(chan struct{})
	close(idle)
	return &pipeListener{name: name, sd: sd, handle: handle, idle: idle}, name, nil
}

// createPipeInstance makes one byte-stream instance of the endpoint. Remote
// clients are rejected by the pipe itself, and the first instance claims the
// name exclusively so that a squatter already holding it fails this startup
// rather than sharing the endpoint with the vault key.
func createPipeInstance(name string, sd *windows.SECURITY_DESCRIPTOR, first bool) (windows.Handle, error) {
	wide, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	open := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		open |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	mode := uint32(windows.PIPE_TYPE_BYTE | windows.PIPE_READMODE_BYTE | windows.PIPE_WAIT | windows.PIPE_REJECT_REMOTE_CLIENTS)
	return windows.CreateNamedPipe(wide, open, mode, windows.PIPE_UNLIMITED_INSTANCES, pipeBuffer, pipeBuffer, 0, &sa)
}

// pipeListener always holds one unconnected instance, so the name never
// becomes free for another process to claim while the daemon runs.
type pipeListener struct {
	name string
	sd   *windows.SECURITY_DESCRIPTOR

	mu      sync.Mutex
	handle  windows.Handle
	closed  bool
	idle    chan struct{}
	overlap windows.Overlapped // The kernel writes here while Accept waits.
	once    sync.Once
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr(l.name) }

// Accept waits for one client and replaces the listening instance before
// handing that one over, so there is no window in which the name has no
// instance at all.
func (l *pipeListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	handle, overlap := l.handle, &l.overlap
	l.idle = make(chan struct{})
	idle := l.idle
	l.mu.Unlock()

	err := connectPipe(handle, overlap)

	l.mu.Lock()
	defer l.mu.Unlock()
	close(idle)
	if err != nil || l.closed {
		return nil, net.ErrClosed // Close releases the handle.
	}
	next, err := createPipeInstance(l.name, l.sd, false)
	if err != nil {
		return nil, errDaemonEndpoint
	}
	conn := newPipeConn(handle, l.name)
	l.handle = next // newPipeConn owns the accepted handle either way.
	if conn == nil {
		return nil, errDaemonEndpoint
	}
	return conn, nil
}

// Close stops admission and interrupts a waiting Accept. A cancellation can
// reach the kernel before the operation it is meant to stop, so it repeats
// until the accept actually ends; only then is the native handle released,
// and cancellation takes the same mutex so it cannot reach a recycled handle.
func (l *pipeListener) Close() error {
	l.once.Do(func() {
		l.mu.Lock()
		l.closed = true
		idle := l.idle
		l.mu.Unlock()
		ticker := time.NewTicker(pipeCancelInterval)
		defer ticker.Stop()
		for {
			select {
			case <-idle:
				l.mu.Lock()
				if l.handle != windows.InvalidHandle {
					windows.CloseHandle(l.handle)
					l.handle = windows.InvalidHandle
				}
				l.mu.Unlock()
				return
			default:
			}
			l.cancel()
			select {
			case <-idle:
			case <-ticker.C:
			}
		}
	})
	return nil
}

func (l *pipeListener) cancel() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.handle != windows.InvalidHandle {
		_ = windows.CancelIoEx(l.handle, &l.overlap)
	}
}

// connectPipe waits for one client on an overlapped instance. A client that
// connected before this call is already accepted, not an error.
func connectPipe(handle windows.Handle, overlap *windows.Overlapped) error {
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(event)
	*overlap = windows.Overlapped{HEvent: event}
	err = windows.ConnectNamedPipe(handle, overlap)
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		var done uint32
		err = windows.GetOverlappedResult(handle, overlap, &done, true)
	}
	if err == nil || errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		return nil
	}
	return err
}

func daemonDial(getenv func(string) string) (net.Conn, error) {
	name := daemonEndpoint(getenv)
	self, err := currentUserSID()
	if name == "" || err != nil {
		return nil, errDaemonEndpoint
	}
	wide, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, errDaemonEndpoint
	}
	var handle windows.Handle
	for attempt := range pipeBusyAttempts {
		// Identification level only: a squatting server must never be able
		// to impersonate this client, even before the owner check below.
		handle, err = windows.CreateFile(wide, windows.GENERIC_READ|windows.GENERIC_WRITE,
			0, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		// Every instance is momentarily busy between a client connecting and
		// the daemon creating its replacement.
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) || attempt == pipeBusyAttempts-1 {
			break
		}
		time.Sleep(pipeBusyInterval)
	}
	if err != nil {
		return nil, errDaemonReach
	}
	// Anti-squatting: nothing is written, and no token is sent, until the
	// pipe this name resolved to is owned by this user.
	if err := pipeOwnedBySelf(handle, self); err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}
	conn := newPipeConn(handle, name)
	if conn == nil {
		return nil, errDaemonReach
	}
	return conn, nil
}

// pipeOwnedBySelf reads the owner of the pipe behind an opened client handle.
// Reading it needs only the READ_CONTROL that the owner-only descriptor
// already grants this user.
func pipeOwnedBySelf(handle windows.Handle, self *windows.SID) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return errDaemonEndpoint
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(self) {
		return errDaemonEndpoint
	}
	return nil
}

// daemonPeerAllowed requires the connected client to run as this user. The
// pipe's descriptor already denies every other principal at connect time;
// this is the independent per-connection check, taken before any byte is
// read. The client's process holds the connection open while it is asked
// about, which is what keeps its process id meaningful here.
func daemonPeerAllowed(conn net.Conn) bool {
	pipe, ok := conn.(*pipeConn)
	if !ok {
		return false
	}
	self, err := currentUserSID()
	if err != nil {
		return false
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(pipe.handle, &pid); err != nil || pid == 0 {
		return false
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return false
	}
	return user.User.Sid.Equals(self)
}

// pipeConn is one connected instance as a net.Conn. The handle is overlapped,
// so os.File registers it with the runtime poller: deadlines work and Close
// interrupts a blocked read, which is what the daemon's close-conns-join-then
// -lock ordering requires.
type pipeConn struct {
	*os.File
	handle windows.Handle
}

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

func (c *pipeConn) LocalAddr() net.Addr  { return pipeAddr(c.Name()) }
func (c *pipeConn) RemoteAddr() net.Addr { return pipeAddr(c.Name()) }

// newPipeConn takes ownership of handle: a nil result means the handle has
// already been released, and the caller must not close it again.
func newPipeConn(handle windows.Handle, name string) *pipeConn {
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		windows.CloseHandle(handle)
		return nil
	}
	// os.NewFile performs I/O synchronously when it cannot associate an
	// overlapped handle with the runtime's completion port, and a connection
	// that cannot carry a deadline or be interrupted by Close is one the
	// daemon cannot join before locking. Refuse it here rather than find out
	// mid-handshake.
	if file.SetDeadline(time.Time{}) != nil {
		file.Close()
		return nil
	}
	return &pipeConn{File: file, handle: handle}
}

// createUserOnlyFile writes a new token file nothing but this user can read.
// Windows file permissions are inherited from the parent directory, which on
// a normal profile also admits SYSTEM and Administrators, so the descriptor
// is set explicitly at creation rather than taken from the directory.
func createUserOnlyFile(path string) (*os.File, error) {
	sd, err := userOnlyDescriptor(fileRights)
	if err != nil {
		return nil, err
	}
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	// CREATE_NEW refuses an existing file, as O_EXCL does on Unix.
	handle, err := windows.CreateFile(wide, windows.GENERIC_WRITE, 0, &sa,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, errAgentToken
	}
	return file, nil
}

// userOnlyFile refuses a token file any other principal can read.
func userOnlyFile(path string) error {
	self, err := currentUserSID()
	if err != nil {
		return errAgentToken
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return errAgentToken
	}
	if descriptorIsUserOnly(sd, self) != nil {
		return errAgentToken
	}
	return nil
}
