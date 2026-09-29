package rescuemap

import (
	"bytes"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"
)

// model is a byte-per-byte reference implementation.
type model []Status

func (md model) set(pos, size int64, st Status) {
	for i := max(pos, 0); i < pos+size && i < int64(len(md)); i++ {
		md[i] = st
	}
}

func checkAgainstModel(t *testing.T, m *Map, md model) {
	t.Helper()
	if err := m.Validate(); err != nil {
		t.Fatalf("invariant violated: %v", err)
	}
	if m.Size() != int64(len(md)) {
		t.Fatalf("size = %d, want %d", m.Size(), len(md))
	}
	for k, b := range m.blocks {
		if k > 0 && m.blocks[k-1].Status == b.Status {
			t.Fatalf("adjacent blocks %d,%d share status %c (not merged)", k-1, k, b.Status)
		}
		for i := b.Pos; i < b.End(); i++ {
			if md[i] != b.Status {
				t.Fatalf("byte %d: map says %c, model says %c", i, b.Status, md[i])
			}
		}
	}
}

func TestSetMatchesModel(t *testing.T) {
	statuses := []Status{NonTried, NonTrimmed, NonScraped, BadSector, Finished}
	rng := rand.New(rand.NewSource(1))
	for trial := 0; trial < 200; trial++ {
		size := int64(1 + rng.Intn(300))
		m := New(size)
		md := make(model, size)
		md.set(0, size, NonTried)
		for op := 0; op < 60; op++ {
			pos := int64(rng.Intn(int(size)+20)) - 10
			n := int64(rng.Intn(int(size)/2 + 2))
			st := statuses[rng.Intn(len(statuses))]
			m.Set(pos, n, st)
			md.set(pos, n, st)
			checkAgainstModel(t, m, md)
		}
	}
}

func TestUnrescued(t *testing.T) {
	m := New(100)
	m.Set(0, 100, Finished)
	m.Set(10, 5, BadSector)
	m.Set(50, 10, NonTried)
	cases := []struct{ pos, size, want int64 }{
		{0, 10, 0},
		{0, 100, 15},
		{12, 2, 2},
		{14, 40, 1 + 4},
		{95, 10, 5}, // 5 bytes past the domain
		{200, 10, 10},
	}
	for _, c := range cases {
		if got := m.Unrescued(c.pos, c.size); got != c.want {
			t.Errorf("Unrescued(%d,%d) = %d, want %d", c.pos, c.size, got, c.want)
		}
	}
}

func TestRoundTripAndSave(t *testing.T) {
	m := New(1 << 20)
	m.Set(4096, 512, BadSector)
	m.Set(0, 4096, Finished)
	m.Set(8192, 1024, NonScraped)
	m.CurrentPos, m.CurrentPhase, m.CurrentPass = 8192, PhaseScraping, 3

	path := filepath.Join(t.TempDir(), "disk.map")
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(path); err != nil { // overwrite must succeed atomically
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.CurrentPos != 8192 || got.CurrentPhase != PhaseScraping || got.CurrentPass != 3 {
		t.Fatalf("status line not preserved: %+v", got)
	}
	if len(got.blocks) != len(m.blocks) {
		t.Fatalf("blocks = %v, want %v", got.blocks, m.blocks)
	}
	for i := range got.blocks {
		if got.blocks[i] != m.blocks[i] {
			t.Fatalf("block %d = %+v, want %+v", i, got.blocks[i], m.blocks[i])
		}
	}
}

func TestParseDdrescueMapfile(t *testing.T) {
	// Verbatim shape of a GNU ddrescue 1.27 mapfile.
	const in = `# Mapfile. Created by GNU ddrescue version 1.27
# Command line: ddrescue -d /dev/sdb sdb.img sdb.map
# Start time:   2024-01-01 10:00:00
# Current time: 2024-01-01 10:05:00
# Finished
# current_pos  current_status  current_pass
0x7470A000     +               1
#      pos        size  status
0x00000000  0x7470A000  +
0x7470A000  0x00001000  -
0x7470B000  0x00005000  +
`
	m, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if m.Size() != 0x74710000 {
		t.Fatalf("size = %#x", m.Size())
	}
	if got := m.Totals()[BadSector]; got != 0x1000 {
		t.Fatalf("bad bytes = %#x", got)
	}
}

func TestParseRejectsGaps(t *testing.T) {
	const in = "0x0 ? 1\n0x0 0x10 +\n0x20 0x10 +\n"
	if _, err := Parse(strings.NewReader(in)); err == nil {
		t.Fatal("expected error for gapped mapfile")
	}
}

func FuzzParse(f *testing.F) {
	var buf bytes.Buffer
	m := New(4096)
	m.Set(512, 512, BadSector)
	m.WriteTo(&buf)
	f.Add(buf.String())
	f.Add("0x0 + 1\n0x0 0x10 +\n")
	f.Fuzz(func(t *testing.T, s string) {
		m, err := Parse(strings.NewReader(s))
		if err != nil {
			return
		}
		if err := m.Validate(); err != nil {
			t.Fatalf("Parse accepted an invalid map: %v", err)
		}
		var out bytes.Buffer
		if _, err := m.WriteTo(&out); err != nil {
			t.Fatal(err)
		}
		m2, err := Parse(&out)
		if err != nil {
			t.Fatalf("re-parse of our own output failed: %v", err)
		}
		if m2.Size() != m.Size() {
			t.Fatalf("round trip changed size")
		}
	})
}
