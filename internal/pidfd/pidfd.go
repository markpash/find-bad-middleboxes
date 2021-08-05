package pidfd

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func Files(pid int) (files []*os.File, err error) {
	const maxFDGap = 32

	defer func() {
		if err != nil {
			for _, file := range files {
				file.Close()
			}
		}
	}()

	if pid == os.Getpid() {
		// Retrieving files from the current process makes the loop below
		// never finish.
		return nil, fmt.Errorf("can't retrieve files from the same process")
	}

	pidfd, err := pidfdOpen(pid, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(pidfd)

	for i, gap := 0, 0; i < int(^uint(0)>>1) && gap < maxFDGap; i++ {
		target, err := pidfdGetFD(pidfd, i, 0)
		if errors.Is(err, unix.EBADF) {
			gap++
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("target fd %d: %s", i, err)
		}
		gap = 0

		keep, err := filter(target)
		if errors.Is(err, unix.ENOTSOCK) {
			unix.Close(target)
		} else if err != nil {
			unix.Close(target)
			return nil, fmt.Errorf("target fd %d: %w", i, err)
		} else if keep {
			files = append(files, os.NewFile(uintptr(target), ""))
		} else {
			unix.Close(target)
		}
	}

	return files, nil
}

func filter(fd int) (bool, error) {
	// get the domain of the socket and reject it if it's not ipv6
	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return false, err
	}
	if domain != unix.AF_INET6 {
		return false, nil
	}

	// get type of the socket, and if it's not tcp, reject it
	soType, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return false, fmt.Errorf("getsockopt(SO_TYPE): %s", err)
	}

	if soType != unix.SOCK_STREAM {
		return false, nil
	}

	// see if the socket is a listening one, if it isn't then reject it
	acceptConn, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	if err != nil {
		return false, fmt.Errorf("getsockopt(SO_ACCEPTCONN): %s", err)
	}

	if acceptConn == 0 {
		// Not a listening socket
		return false, nil
	}

	return true, nil
}

func pidfdOpen(pid, flags int) (int, error) {
	fd, _, errNo := unix.Syscall(unix.SYS_PIDFD_OPEN, uintptr(pid), uintptr(flags), 0)
	if errNo != 0 {
		return -1, fmt.Errorf("pidfd_open(%d): %w", pid, errNo)
	}
	return int(fd), nil
}

func pidfdGetFD(pidfd, target, flags int) (int, error) {
	fd, _, errNo := unix.Syscall(unix.SYS_PIDFD_GETFD, uintptr(pidfd), uintptr(target), uintptr(flags))
	if errNo != 0 {
		return -1, fmt.Errorf("pidfd_getfd(%d, %d): %w", pidfd, target, errNo)
	}
	return int(fd), nil
}
