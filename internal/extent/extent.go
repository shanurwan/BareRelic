// Package extent describes where recovered bytes live on the source.
package extent

import (
	"io"
)

// Extent is a byte range on a source. A negative Offset denotes a sparse
// (hole) range that reads as zeros.
type Extent struct {
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
}

// Sparse reports whether the extent is a hole.
func (e Extent) Sparse() bool { return e.Offset < 0 }

// List is an ordered list of extents that together form one file.
type List []Extent

// Total returns the combined length.
func (l List) Total() int64 {
	var n int64
	for _, e := range l {
		n += e.Length
	}
	return n
}

// Append adds an extent, coalescing it with the previous one when contiguous.
func (l List) Append(e Extent) List {
	if e.Length <= 0 {
		return l
	}
	if n := len(l); n > 0 {
		last := &l[n-1]
		if last.Sparse() && e.Sparse() {
			last.Length += e.Length
			return l
		}
		if !last.Sparse() && !e.Sparse() && last.Offset+last.Length == e.Offset {
			last.Length += e.Length
			return l
		}
	}
	return append(l, e)
}

// Truncate limits the list to n bytes.
func (l List) Truncate(n int64) List {
	var out List
	for _, e := range l {
		if n <= 0 {
			break
		}
		if e.Length > n {
			e.Length = n
		}
		out = append(out, e)
		n -= e.Length
	}
	return out
}

// Shift returns a copy with every non-sparse offset moved by base (used to
// turn volume-relative extents into source-absolute ones).
func (l List) Shift(base int64) List {
	out := make(List, len(l))
	for i, e := range l {
		if !e.Sparse() {
			e.Offset += base
		}
		out[i] = e
	}
	return out
}

// Physical returns only the non-sparse extents.
func (l List) Physical() List {
	var out List
	for _, e := range l {
		if !e.Sparse() {
			out = append(out, e)
		}
	}
	return out
}

// Reader returns a reader over the concatenated extents of r.
func (l List) Reader(r io.ReaderAt) io.Reader {
	readers := make([]io.Reader, 0, len(l))
	for _, e := range l {
		if e.Sparse() {
			readers = append(readers, io.LimitReader(zeros{}, e.Length))
		} else {
			readers = append(readers, &strictSection{r: io.NewSectionReader(r, e.Offset, e.Length), want: e.Length})
		}
	}
	return io.MultiReader(readers...)
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// strictSection turns a premature EOF (extent past the end of the source)
// into io.ErrUnexpectedEOF so truncation is reported rather than silent.
type strictSection struct {
	r    *io.SectionReader
	want int64
	got  int64
}

func (s *strictSection) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	s.got += int64(n)
	if err == io.EOF && s.got < s.want {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}
