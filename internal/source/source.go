// Package source opens evidence (image files and raw block devices) strictly
// read-only and presents them as a sized io.ReaderAt.
//
// Nothing in this package can write to a source: files and devices are opened
// with os.Open (O_RDONLY / GENERIC_READ) and no write method is exposed.
package source

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// DefaultSectorSize is assumed for regular image files.
const DefaultSectorSize = 512

// Source is read-only, randomly addressable evidence.
type Source interface {
	io.ReaderAt
	// Size is the number of addressable bytes.
	Size() int64
	// SectorSize is the device's logical sector size (512 for image files).
	SectorSize() int
	// Path is the path the source was opened from.
	Path() string
	// IsDevice reports whether the source is a raw block/character device.
	IsDevice() bool
	Close() error
}

type fileSource struct {
	f          *os.File
	r          io.ReaderAt
	size       int64
	sectorSize int
	path       string
	device     bool
}

func (s *fileSource) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("source: negative offset")
	}
	if off >= s.size {
		return 0, io.EOF
	}
	short := false
	if rem := s.size - off; int64(len(p)) > rem {
		p = p[:rem]
		short = true
	}
	n, err := s.r.ReadAt(p, off)
	if err == nil && short {
		err = io.EOF
	}
	return n, err
}

func (s *fileSource) Size() int64     { return s.size }
func (s *fileSource) SectorSize() int { return s.sectorSize }
func (s *fileSource) Path() string    { return s.path }
func (s *fileSource) IsDevice() bool  { return s.device }
func (s *fileSource) Close() error    { return s.f.Close() }
func (s *fileSource) String() string  { return s.path }

// Open opens path read-only. Regular files are treated as images; devices
// have their size and logical sector size queried from the OS, and reads are
// transparently aligned to sector boundaries (required for raw devices on
// Windows and for O_DIRECT-style access elsewhere).
func Open(path string) (Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open source read-only: %w", err)
	}
	src := &fileSource{f: f, r: f, path: path, sectorSize: DefaultSectorSize}

	fi, statErr := f.Stat()
	if statErr == nil && fi.Mode().IsRegular() {
		src.size = fi.Size()
		return src, nil
	}

	size, sector, err := deviceGeometry(f)
	if err != nil {
		f.Close()
		if statErr != nil {
			return nil, fmt.Errorf("source %q is neither a regular file nor a queryable device: stat: %v; device: %w", path, statErr, err)
		}
		return nil, fmt.Errorf("query device geometry of %q: %w", path, err)
	}
	if sector <= 0 || sector&(sector-1) != 0 {
		sector = DefaultSectorSize
	}
	src.size = size
	src.sectorSize = sector
	src.device = true
	src.r = &alignedReader{r: f, sectorSize: int64(sector)}
	return src, nil
}

// alignedReader turns arbitrary reads into sector-aligned reads.
type alignedReader struct {
	r          io.ReaderAt
	sectorSize int64
}

func (a *alignedReader) ReadAt(p []byte, off int64) (int, error) {
	ss := a.sectorSize
	if off%ss == 0 && int64(len(p))%ss == 0 {
		return a.r.ReadAt(p, off)
	}
	start := off - off%ss
	end := off + int64(len(p))
	if rem := end % ss; rem != 0 {
		end += ss - rem
	}
	buf := make([]byte, end-start)
	n, err := a.r.ReadAt(buf, start)
	skip := int(off - start)
	if n <= skip {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return 0, err
	}
	c := copy(p, buf[skip:n])
	if c < len(p) && err == nil {
		err = io.EOF
	}
	if c == len(p) {
		err = nil
	}
	return c, err
}
