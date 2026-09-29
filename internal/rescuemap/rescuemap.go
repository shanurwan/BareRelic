// Package rescuemap tracks which byte ranges of a source have been rescued,
// using the GNU ddrescue mapfile format so maps interoperate with ddrescue,
// ddrescuelog and ddrescueview.
//
// A Map always covers [0, Size) with contiguous, non-overlapping, sorted
// blocks; adjacent blocks with the same status are merged.
package rescuemap

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Status is a ddrescue block status character.
type Status byte

const (
	NonTried   Status = '?' // not read yet
	NonTrimmed Status = '*' // failed during copy; edges not yet trimmed
	NonScraped Status = '/' // interior of a failed area; not yet read sector by sector
	BadSector  Status = '-' // failed sector-granular read
	Finished   Status = '+' // rescued
)

// Valid reports whether s is a known block status.
func (s Status) Valid() bool {
	switch s {
	case NonTried, NonTrimmed, NonScraped, BadSector, Finished:
		return true
	}
	return false
}

func (s Status) String() string {
	switch s {
	case NonTried:
		return "non-tried"
	case NonTrimmed:
		return "non-trimmed"
	case NonScraped:
		return "non-scraped"
	case BadSector:
		return "bad-sector"
	case Finished:
		return "finished"
	}
	return fmt.Sprintf("unknown(%q)", byte(s))
}

// Phase is the ddrescue "current_status" character.
type Phase byte

const (
	PhaseCopying  Phase = '?'
	PhaseTrimming Phase = '*'
	PhaseScraping Phase = '/'
	PhaseRetrying Phase = '-'
	PhaseFinished Phase = '+'
)

// Valid reports whether p is a phase ddrescue can write ('F' filling and
// 'G' generating are ddrescue-only phases, accepted for interoperability).
func (p Phase) Valid() bool {
	switch p {
	case PhaseCopying, PhaseTrimming, PhaseScraping, PhaseRetrying, PhaseFinished, 'F', 'G':
		return true
	}
	return false
}

// Block is a contiguous range with one status.
type Block struct {
	Pos    int64
	Size   int64
	Status Status
}

// End returns the exclusive end offset.
func (b Block) End() int64 { return b.Pos + b.Size }

// Map is a rescue map. It is not safe for concurrent use.
type Map struct {
	blocks []Block

	CurrentPos   int64
	CurrentPhase Phase
	CurrentPass  int
}

// New returns a map for a domain of size bytes, entirely non-tried.
func New(size int64) *Map {
	m := &Map{CurrentPhase: PhaseCopying, CurrentPass: 1}
	if size > 0 {
		m.blocks = []Block{{Pos: 0, Size: size, Status: NonTried}}
	}
	return m
}

// Size returns the size of the mapped domain.
func (m *Map) Size() int64 {
	if len(m.blocks) == 0 {
		return 0
	}
	return m.blocks[len(m.blocks)-1].End()
}

// Blocks returns a copy of the block list.
func (m *Map) Blocks() []Block {
	return append([]Block(nil), m.blocks...)
}

// Set marks [pos, pos+size) with status st. The range is clipped to the domain.
func (m *Map) Set(pos, size int64, st Status) {
	if size <= 0 {
		return
	}
	end := pos + size
	if pos < 0 {
		pos = 0
	}
	if dom := m.Size(); end > dom {
		end = dom
	}
	if pos >= end {
		return
	}
	// First block whose end is beyond pos, and first block starting at/after end.
	i := sort.Search(len(m.blocks), func(k int) bool { return m.blocks[k].End() > pos })
	j := sort.Search(len(m.blocks), func(k int) bool { return m.blocks[k].Pos >= end })

	repl := make([]Block, 0, 3)
	if first := m.blocks[i]; first.Pos < pos {
		repl = append(repl, Block{Pos: first.Pos, Size: pos - first.Pos, Status: first.Status})
	}
	repl = append(repl, Block{Pos: pos, Size: end - pos, Status: st})
	if last := m.blocks[j-1]; last.End() > end {
		repl = append(repl, Block{Pos: end, Size: last.End() - end, Status: last.Status})
	}

	// Widen the window by one neighbour on each side so merges can happen.
	lo, hi := i, j
	if lo > 0 {
		lo--
		repl = append([]Block{m.blocks[lo]}, repl...)
	}
	if hi < len(m.blocks) {
		repl = append(repl, m.blocks[hi])
		hi++
	}
	merged := repl[:1]
	for _, b := range repl[1:] {
		top := &merged[len(merged)-1]
		if top.Status == b.Status && top.End() == b.Pos {
			top.Size += b.Size
			continue
		}
		merged = append(merged, b)
	}
	tail := append([]Block(nil), m.blocks[hi:]...)
	m.blocks = append(append(m.blocks[:lo], merged...), tail...)
}

// Regions returns all blocks with status st, in ascending order.
func (m *Map) Regions(st Status) []Block {
	var out []Block
	for _, b := range m.blocks {
		if b.Status == st {
			out = append(out, b)
		}
	}
	return out
}

// Totals returns the number of bytes in each status.
func (m *Map) Totals() map[Status]int64 {
	t := make(map[Status]int64, 5)
	for _, b := range m.blocks {
		t[b.Status] += b.Size
	}
	return t
}

// Unrescued returns how many bytes of [pos, pos+size) are not Finished.
// Bytes outside the mapped domain count as unrescued.
func (m *Map) Unrescued(pos, size int64) int64 {
	if size <= 0 {
		return 0
	}
	end := pos + size
	var missing int64
	if dom := m.Size(); end > dom {
		if pos >= dom {
			return size
		}
		missing += end - dom
		end = dom
	}
	i := sort.Search(len(m.blocks), func(k int) bool { return m.blocks[k].End() > pos })
	for ; i < len(m.blocks) && m.blocks[i].Pos < end; i++ {
		b := m.blocks[i]
		if b.Status == Finished {
			continue
		}
		missing += min(end, b.End()) - max(pos, b.Pos)
	}
	return missing
}

// Validate checks the structural invariants.
func (m *Map) Validate() error {
	var next int64
	for k, b := range m.blocks {
		if b.Pos != next {
			return fmt.Errorf("block %d at 0x%X: expected position 0x%X (gap or overlap)", k, b.Pos, next)
		}
		if b.Size <= 0 {
			return fmt.Errorf("block %d at 0x%X: non-positive size %d", k, b.Pos, b.Size)
		}
		if !b.Status.Valid() {
			return fmt.Errorf("block %d at 0x%X: invalid status %q", k, b.Pos, byte(b.Status))
		}
		next = b.End()
	}
	return nil
}

// WriteTo writes the map in ddrescue mapfile format.
func (m *Map) WriteTo(w io.Writer) (int64, error) {
	bw := bufio.NewWriter(w)
	cw := &countWriter{w: bw}
	fmt.Fprintf(cw, "# Mapfile. Created by barerelic (GNU ddrescue mapfile format)\n")
	fmt.Fprintf(cw, "# Updated: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(cw, "# current_pos  current_status  current_pass\n")
	fmt.Fprintf(cw, "0x%08X     %c               %d\n", m.CurrentPos, byte(m.CurrentPhase), m.CurrentPass)
	fmt.Fprintf(cw, "#      pos        size  status\n")
	for _, b := range m.blocks {
		fmt.Fprintf(cw, "0x%08X  0x%08X  %c\n", b.Pos, b.Size, byte(b.Status))
	}
	if cw.err != nil {
		return cw.n, cw.err
	}
	return cw.n, bw.Flush()
}

type countWriter struct {
	w   io.Writer
	n   int64
	err error
}

func (c *countWriter) Write(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	n, err := c.w.Write(p)
	c.n += int64(n)
	c.err = err
	return n, err
}

// Parse reads a ddrescue mapfile.
func Parse(r io.Reader) (*Map, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	m := &Map{}
	haveStatusLine := false
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if !haveStatusLine {
			if len(fields) < 2 || len(fields) > 3 {
				return nil, fmt.Errorf("line %d: malformed status line %q", line, text)
			}
			pos, err := strconv.ParseInt(fields[0], 0, 64)
			if err != nil || pos < 0 {
				return nil, fmt.Errorf("line %d: bad current_pos %q", line, fields[0])
			}
			if len(fields[1]) != 1 || !Phase(fields[1][0]).Valid() {
				return nil, fmt.Errorf("line %d: bad current_status %q", line, fields[1])
			}
			m.CurrentPos, m.CurrentPhase, m.CurrentPass = pos, Phase(fields[1][0]), 1
			if len(fields) == 3 {
				pass, err := strconv.Atoi(fields[2])
				if err != nil || pass < 1 {
					return nil, fmt.Errorf("line %d: bad current_pass %q", line, fields[2])
				}
				m.CurrentPass = pass
			}
			haveStatusLine = true
			continue
		}
		if len(fields) != 3 || len(fields[2]) != 1 {
			return nil, fmt.Errorf("line %d: malformed block line %q", line, text)
		}
		pos, err1 := strconv.ParseInt(fields[0], 0, 64)
		size, err2 := strconv.ParseInt(fields[1], 0, 64)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("line %d: bad number in %q", line, text)
		}
		b := Block{Pos: pos, Size: size, Status: Status(fields[2][0])}
		if n := len(m.blocks); n > 0 && m.blocks[n-1].Status == b.Status && m.blocks[n-1].End() == b.Pos {
			m.blocks[n-1].Size += b.Size
		} else {
			m.blocks = append(m.blocks, b)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !haveStatusLine {
		return nil, errors.New("mapfile has no status line")
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("mapfile invalid: %w", err)
	}
	return m, nil
}

// Load reads a mapfile from disk.
func Load(path string) (*Map, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Save writes the map atomically and durably: a temporary file in the same
// directory is written and fsynced, then renamed over path. A crash leaves
// either the previous map or the new one, never a torn file.
func (m *Map) Save(path string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp mapfile: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()
	if _, err := m.WriteTo(tmp); err != nil {
		tmp.Close()
		return fmt.Errorf("write mapfile: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync mapfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace mapfile: %w", err)
	}
	tmpName = ""
	syncDir(dir)
	return nil
}
