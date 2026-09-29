//go:build darwin

package source

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	dkiocGetBlockSize  = 0x40046418 // DKIOCGETBLOCKSIZE
	dkiocGetBlockCount = 0x40086419 // DKIOCGETBLOCKCOUNT
)

func deviceGeometry(f *os.File) (int64, int, error) {
	var bs uint32
	var count uint64
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), dkiocGetBlockSize, uintptr(unsafe.Pointer(&bs))); errno != 0 {
		return 0, 0, fmt.Errorf("DKIOCGETBLOCKSIZE: %w", errno)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), dkiocGetBlockCount, uintptr(unsafe.Pointer(&count))); errno != 0 {
		return 0, 0, fmt.Errorf("DKIOCGETBLOCKCOUNT: %w", errno)
	}
	return int64(count) * int64(bs), int(bs), nil
}
