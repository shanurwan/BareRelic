//go:build linux

package source

import (
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"
)

const blkSSZGet = 0x1268 // BLKSSZGET: logical sector size

func deviceGeometry(f *os.File) (int64, int, error) {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, 0, fmt.Errorf("seek to end: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, 0, fmt.Errorf("seek to start: %w", err)
	}
	var ss int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), blkSSZGet, uintptr(unsafe.Pointer(&ss))); errno != 0 {
		ss = DefaultSectorSize
	}
	return size, int(ss), nil
}
