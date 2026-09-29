package extent

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestAppendCoalesces(t *testing.T) {
	var l List
	l = l.Append(Extent{0, 10})
	l = l.Append(Extent{10, 5})  // contiguous
	l = l.Append(Extent{-1, 4})  // hole
	l = l.Append(Extent{-1, 4})  // hole
	l = l.Append(Extent{100, 1}) // gap
	l = l.Append(Extent{200, 0}) // empty: dropped
	want := List{{0, 15}, {-1, 8}, {100, 1}}
	if len(l) != len(want) {
		t.Fatalf("got %v, want %v", l, want)
	}
	for i := range want {
		if l[i] != want[i] {
			t.Fatalf("got %v, want %v", l, want)
		}
	}
	if l.Total() != 24 || len(l.Physical()) != 2 {
		t.Fatalf("total %d physical %v", l.Total(), l.Physical())
	}
}

func TestReaderAndShift(t *testing.T) {
	src := []byte("0123456789ABCDEF")
	l := List{{2, 3}, {-1, 2}, {10, 2}}
	got, err := io.ReadAll(l.Reader(bytes.NewReader(src)))
	if err != nil || string(got) != "234\x00\x00AB" {
		t.Fatalf("got %q, %v", got, err)
	}
	if s := l.Shift(100); s[0].Offset != 102 || s[1].Offset != -1 || l[0].Offset != 2 {
		t.Fatalf("shift = %v (original %v)", s, l)
	}
	if tr := l.Truncate(4); tr.Total() != 4 || len(tr) != 2 {
		t.Fatalf("truncate = %v", tr)
	}
}

func TestReaderReportsTruncatedSource(t *testing.T) {
	_, err := io.ReadAll(List{{10, 100}}.Reader(bytes.NewReader(make([]byte, 20))))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("extent past end of source must fail loudly, got %v", err)
	}
}
