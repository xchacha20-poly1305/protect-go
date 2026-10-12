package protect

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// listenerSecurityDescriptor gives SYSTEM, Administrators and the owner full
// control of the socket file, and every other user the read and write access
// that connect requires. It is the counterpart of mode 0777 on Unix.
const listenerSecurityDescriptor = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FRFW;;;WD)"

// sioAFUnixGetPeerPID is SIO_AF_UNIX_GETPEERPID from afunix.h.
const sioAFUnixGetPeerPID = windows.IOC_OUT | windows.IOC_VENDOR | 256

func allowAllUsers(path string) error {
	securityDescriptor, err := windows.SecurityDescriptorFromString(listenerSecurityDescriptor)
	if err != nil {
		return err
	}
	dacl, _, err := securityDescriptor.DACL()
	if err != nil {
		return err
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// An AF_UNIX socket file is a reparse point that cannot be followed.
	file, err := windows.CreateFile(pathPointer, windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return fmt.Errorf("open socket file: %w", err)
	}
	defer windows.CloseHandle(file)
	err = windows.SetSecurityInfo(file, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("set socket file DACL: %w", err)
	}
	return nil
}

// receiveSocket reads the handle value a client sends and duplicates that
// handle out of the client process, which it identifies by the peer of conn.
// The client can therefore name only a handle it holds itself.
func receiveSocket(conn *net.UnixConn) (int, error) {
	// Open the peer before reading the request, while its process identifier
	// most likely still names the process that connected.
	processID, err := peerProcessID(conn)
	if err != nil {
		return -1, fmt.Errorf("protect: identify peer: %w", err)
	}
	process, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, processID)
	if err != nil {
		return -1, fmt.Errorf("protect: open client process %d: %w", processID, err)
	}
	defer windows.CloseHandle(process)
	request := make([]byte, requestLength)
	_, err = io.ReadFull(conn, request)
	if err != nil {
		return -1, fmt.Errorf("protect: read request: %w", err)
	}
	clientHandle := windows.Handle(binary.LittleEndian.Uint64(request))
	var handle windows.Handle
	err = windows.DuplicateHandle(process, clientHandle, windows.CurrentProcess(), &handle,
		0, false, windows.DUPLICATE_SAME_ACCESS)
	if err != nil {
		return -1, fmt.Errorf("protect: duplicate handle %#x of process %d: %w", clientHandle, processID, err)
	}
	// Reading the protocol also fails on a handle that is not a socket.
	info, err := protocolInfo(handle)
	if err != nil {
		closeSocket(int(handle))
		return -1, err
	}
	// A layered provider keeps state in the client process that a duplicated
	// handle does not carry. Only a kernel socket handle is usable here.
	if info.ServiceFlags1&windows.XP1_IFS_HANDLES == 0 {
		closeSocket(int(handle))
		return -1, errors.New("protect: socket provider does not use kernel handles")
	}
	return int(handle), nil
}

func peerProcessID(conn *net.UnixConn) (uint32, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var processID uint32
	var ioctlErr error
	err = rawConn.Control(func(fd uintptr) {
		var returned uint32
		ioctlErr = windows.WSAIoctl(windows.Handle(fd), sioAFUnixGetPeerPID, nil, 0,
			(*byte)(unsafe.Pointer(&processID)), uint32(unsafe.Sizeof(processID)), &returned, nil, 0)
	})
	if err != nil {
		return 0, err
	}
	if ioctlErr != nil {
		return 0, ioctlErr
	}
	return processID, nil
}

// closeSocket closes a handle obtained by receiveSocket. A handle that Winsock
// does not recognize as a socket still has to be closed as a plain handle.
func closeSocket(fd int) {
	handle := windows.Handle(fd)
	if windows.Closesocket(handle) != nil {
		_ = windows.CloseHandle(handle)
	}
}
