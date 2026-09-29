//go:build !windows && !linux && !darwin

package source

import (
	"fmt"
	"io"
	"os"
)

func deviceGeometry(f *os.File) (int64, int, error) {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, 0, fmt.Errorf("seek to end: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, 0, fmt.Errorf("seek to start: %w", err)
	}
	return size, DefaultSectorSize, nil
}
