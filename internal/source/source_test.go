package source

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// strictDevice rejects unaligned I/O the way raw devices do on Windows.
type strictDevice struct {
	data []byte
	ss   int64
}

func (d *strictDevice) ReadAt(p []byte, off int64) (int, error) {
	if off%d.ss != 0 || int64(len(p))%d.ss != 0 {
		return 0, errors.New("unaligned device I/O")
	}
	if off >= int64(len(d.data)) {
		return 0, io.EOF
	}
	n := copy(p, d.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestAlignedReader(t *testing.T) {
	data := make([]byte, 64*1024)
	rand.New(rand.NewSource(1)).Read(data)
	a := &alignedReader{r: &strictDevice{data: data, ss: 4096}, sectorSize: 4096}
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 500; i++ {
		off := int64(rng.Intn(len(data)))
		n := rng.Intn(10000)
		p := make([]byte, n)
		got, err := a.ReadAt(p, off)
		want := min(n, len(data)-int(off))
		if got != want {
			t.Fatalf("ReadAt(%d, %d) = %d, want %d (err %v)", n, off, got, want, err)
		}
		if got < n && err == nil {
			t.Fatalf("short read without error at %d", off)
		}
		if !bytes.Equal(p[:got], data[off:off+int64(got)]) {
			t.Fatalf("content mismatch at %d", off)
		}
	}
}

func TestOpenFileIsReadOnlyAndSized(t *testing.T) {
	p := filepath.Join(t.TempDir(), "img.dd")
	if err := os.WriteFile(p, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Size() != 10 || s.SectorSize() != DefaultSectorSize || s.IsDevice() {
		t.Fatalf("size %d sector %d device %v", s.Size(), s.SectorSize(), s.IsDevice())
	}
	if _, ok := s.(io.WriterAt); ok {
		t.Fatal("a Source must not expose a write method")
	}
	buf := make([]byte, 6)
	n, err := s.ReadAt(buf, 7)
	if n != 3 || err != io.EOF || string(buf[:n]) != "789" {
		t.Fatalf("read past end: n=%d err=%v %q", n, err, buf[:n])
	}
	if _, err := s.ReadAt(buf, 10); err != io.EOF {
		t.Fatalf("read at end: %v", err)
	}
}
