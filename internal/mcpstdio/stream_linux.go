package mcpstdio

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ReadHalfClosed is requested only for stdin; it detects peer SHUT_WR even
// when buffered protocol bytes remain. The watcher does not consume bytes.
const ReadHalfClosed = unix.POLLRDHUP

func unnamedUnixPair(fd int) bool {
	return unnamedUnixAddress(fd, unix.SYS_GETSOCKNAME) && unnamedUnixAddress(fd, unix.SYS_GETPEERNAME)
}

func unnamedUnixAddress(fd int, call uintptr) bool {
	var address unix.RawSockaddrUnix
	length := uint32(unsafe.Sizeof(address))
	// x/sys's decoded SockaddrUnix loses the returned length and maps both an
	// unnamed address and an empty abstract name to "@". Keep the kernel's
	// length instead. Only fixed family/length metadata is inspected; sun_path
	// is never interpreted or exposed. Pointers remain direct syscall args.
	_, _, errno := syscall.Syscall(call, uintptr(fd), uintptr(unsafe.Pointer(&address)), uintptr(unsafe.Pointer(&length)))
	return errno == 0 && address.Family == unix.AF_UNIX && length == uint32(unsafe.Offsetof(address.Path))
}
