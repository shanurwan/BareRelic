package carve

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// ErrInvalid is returned by validators for candidates that are not real files.
var ErrInvalid = errors.New("carve: invalid structure")

func invalid() (Result, error) { return Result{}, ErrInvalid }

// Src gives validators bounded access to a candidate. Positions are relative
// to the candidate start; nothing beyond limit is ever read.
type Src struct {
	r     io.ReaderAt
	off   int64
	limit int64
}

// At reads n bytes at relative position rel.
func (s *Src) At(rel int64, n int) ([]byte, error) {
	if rel < 0 || n < 0 || rel+int64(n) > s.limit {
		return nil, ErrInvalid
	}
	b := make([]byte, n)
	if _, err := s.r.ReadAt(b, s.off+rel); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *Src) u16le(rel int64) (uint32, error) {
	b, err := s.At(rel, 2)
	if err != nil {
		return 0, err
	}
	return uint32(binary.LittleEndian.Uint16(b)), nil
}

func (s *Src) u32le(rel int64) (uint32, error) {
	b, err := s.At(rel, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (s *Src) u64le(rel int64) (uint64, error) {
	b, err := s.At(rel, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

// Seq returns a sequential reader starting at rel.
func (s *Src) Seq(rel int64) *Seq {
	sr := io.NewSectionReader(s.r, s.off+rel, max(0, s.limit-rel))
	return &Seq{br: bufio.NewReaderSize(sr, 64<<10), pos: rel}
}

// Seq is a bounded, position-tracking sequential reader.
type Seq struct {
	br  *bufio.Reader
	pos int64
}

// Pos returns the position relative to the candidate start.
func (q *Seq) Pos() int64 { return q.pos }

func (q *Seq) ReadByte() (byte, error) {
	b, err := q.br.ReadByte()
	if err == nil {
		q.pos++
	}
	return b, err
}

func (q *Seq) Read(p []byte) (int, error) {
	n, err := q.br.Read(p)
	q.pos += int64(n)
	return n, err
}

// Full reads exactly n bytes.
func (q *Seq) Full(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(q, b)
	return b, err
}

// Skip discards n bytes.
func (q *Seq) Skip(n int64) error {
	for n > 0 {
		k, err := q.br.Discard(int(min(n, 1<<30)))
		q.pos += int64(k)
		n -= int64(k)
		if err != nil {
			return err
		}
	}
	return nil
}

func (q *Seq) u16be() (uint32, error) {
	b, err := q.Full(2)
	if err != nil {
		return 0, err
	}
	return uint32(binary.BigEndian.Uint16(b)), nil
}

// findForward returns the relative position of the first occurrence of pat
// at or after rel, searching at most window bytes.
func (s *Src) findForward(pat []byte, rel, window int64) (int64, error) {
	const block = 256 << 10
	buf := make([]byte, block+len(pat))
	end := min(s.limit, rel+window)
	for p := rel; p < end; p += block {
		n, _ := s.r.ReadAt(buf[:min(int64(len(buf)), s.limit-p)], s.off+p)
		if n < len(pat) {
			break
		}
		if i := bytes.Index(buf[:n], pat); i >= 0 && p+int64(i) < end {
			return p + int64(i), nil
		}
	}
	return -1, ErrInvalid
}
