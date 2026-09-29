//go:build windows

package source

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	ioctlDiskGetLengthInfo        = 0x0007405C
	ioctlDiskGetDriveGeometryEx   = 0x000700A0
	diskGeometryBytesPerSectorOff = 20
)

// deviceGeometry queries \\.\PhysicalDriveN or \\.\X: handles.
func deviceGeometry(f *os.File) (int64, int, error) {
	h := syscall.Handle(f.Fd())

	var length [8]byte
	var returned uint32
	if err := syscall.DeviceIoControl(h, ioctlDiskGetLengthInfo, nil, 0,
		&length[0], uint32(len(length)), &returned, nil); err != nil {
		return 0, 0, fmt.Errorf("IOCTL_DISK_GET_LENGTH_INFO: %w (raw devices require an elevated prompt)", err)
	}
	size := int64(binary.LittleEndian.Uint64(length[:]))

	sector := DefaultSectorSize
	geo := make([]byte, 256)
	if err := syscall.DeviceIoControl(h, ioctlDiskGetDriveGeometryEx, nil, 0,
		(*byte)(unsafe.Pointer(&geo[0])), uint32(len(geo)), &returned, nil); err == nil && returned >= 24 {
		sector = int(binary.LittleEndian.Uint32(geo[diskGeometryBytesPerSectorOff:]))
	}
	return size, sector, nil
}
