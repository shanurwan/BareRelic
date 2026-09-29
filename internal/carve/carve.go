// Package carve recovers files from raw bytes without file-system metadata:
// unallocated space, formatted media, damaged volumes, or whole disks.
//
// A header signature only nominates a candidate. Every format has a
// validator that walks the file's own structure (chunk CRCs, box sizes,
// central directories, page counts, ...) to decide whether the candidate is
// real and exactly how long it is. Candidates that fail validation are
// discarded rather than emitted as fixed-size junk, which keeps false
// positives low. Carving assumes contiguous files; fragmented files are
// recovered only up to the first fragment boundary, if at all.
package carve

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Validation levels.
const (
	Structural = "structural" // internal structure (sizes, CRCs, tables) verified end to end
	Heuristic  = "heuristic"  // end located by searching for a footer
)

// Result is a validator's verdict on a candidate.
type Result struct {
	Length     int64
	Ext        string
	Validation string
	Notes      []string
}

// Signature describes one carvable format.
type Signature struct {
	Name        string // stable identifier used by --types
	Ext         string // default extension
	Magic       []byte
	MagicOffset int
	MaxSize     int64
	Validate    func(s *Src) (Result, error)
}

// Signatures is the built-in registry.
var Signatures = []*Signature{
	{Name: "jpeg", Ext: "jpg", Magic: []byte{0xFF, 0xD8, 0xFF}, MaxSize: 128 << 20, Validate: validateJPEG},
	{Name: "png", Ext: "png", Magic: []byte("\x89PNG\r\n\x1a\n"), MaxSize: 256 << 20, Validate: validatePNG},
	{Name: "gif", Ext: "gif", Magic: []byte("GIF8"), MaxSize: 64 << 20, Validate: validateGIF},
	{Name: "bmp", Ext: "bmp", Magic: []byte("BM"), MaxSize: 256 << 20, Validate: validateBMP},
	{Name: "pdf", Ext: "pdf", Magic: []byte("%PDF-"), MaxSize: 512 << 20, Validate: validatePDF},
	{Name: "zip", Ext: "zip", Magic: []byte("PK\x03\x04"), MaxSize: 8 << 30, Validate: validateZIP},
	{Name: "gzip", Ext: "gz", Magic: []byte{0x1F, 0x8B, 0x08}, MaxSize: 8 << 30, Validate: validateGzip},
	{Name: "7z", Ext: "7z", Magic: []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}, MaxSize: 16 << 30, Validate: validate7z},
	{Name: "sqlite", Ext: "sqlite", Magic: []byte("SQLite format 3\x00"), MaxSize: 16 << 30, Validate: validateSQLite},
	{Name: "ole", Ext: "ole", Magic: []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, MaxSize: 2 << 30, Validate: validateOLE},
	{Name: "riff", Ext: "riff", Magic: []byte("RIFF"), MaxSize: 4 << 30, Validate: validateRIFF},
	{Name: "isobmff", Ext: "mp4", Magic: []byte("ftyp"), MagicOffset: 4, MaxSize: 64 << 30, Validate: validateISOBMFF},
	{Name: "pe", Ext: "exe", Magic: []byte("MZ"), MaxSize: 2 << 30, Validate: validatePE},
	{Name: "elf", Ext: "elf", Magic: []byte("\x7fELF"), MaxSize: 2 << 30, Validate: validateELF},
}

// Lookup resolves type names; an empty list selects every signature.
func Lookup(names []string) ([]*Signature, error) {
	if len(names) == 0 {
		return Signatures, nil
	}
	byName := map[string]*Signature{}
	for _, s := range Signatures {
		byName[s.Name] = s
	}
	aliases := map[string]string{"jpg": "jpeg", "mp4": "isobmff", "mov": "isobmff", "docx": "zip", "xlsx": "zip",
		"pptx": "zip", "doc": "ole", "xls": "ole", "ppt": "ole", "wav": "riff", "avi": "riff", "webp": "riff",
		"exe": "pe", "dll": "pe", "gz": "gzip", "db": "sqlite"}
	var out []*Signature
	seen := map[string]bool{}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if a, ok := aliases[n]; ok {
			n = a
		}
		s, ok := byName[n]
		if !ok {
			return nil, fmt.Errorf("unknown carve type %q (known: %s)", n, strings.Join(Names(), ", "))
		}
		if !seen[n] {
			out = append(out, s)
			seen[n] = true
		}
	}
	return out, nil
}

// Names lists the registry's type names.
func Names() []string {
	var n []string
	for _, s := range Signatures {
		n = append(n, s.Name)
	}
	return n
}

// Options control a scan.
type Options struct {
	Signatures []*Signature
	Align      int64 // candidate alignment; 512 matches sector-aligned file starts, 1 finds embedded files
	Start, End int64 // byte range; End 0 = to the end of the source
	NoSkip     bool  // keep scanning inside carved files (finds embedded thumbnails, archives in archives)
	MinSize    int64
	Progress   func(pos int64)
}

// Match is a validated carved file.
type Match struct {
	Offset     int64
	Length     int64
	Type       string
	Ext        string
	Validation string
	Notes      []string
}

// Stats summarise a scan.
type Stats struct {
	Scanned    int64            `json:"scanned"`
	Candidates int64            `json:"candidates"`
	Carved     map[string]int64 `json:"carved"`
	Rejected   map[string]int64 `json:"rejected"`
	ReadErrors int64            `json:"read_errors"`
}

const (
	chunkSize = 8 << 20
	headroom  = 64
)

// Scan carves r in [Start, End). fn is called for every validated match in
// ascending offset order.
func Scan(ctx context.Context, r io.ReaderAt, size int64, opt Options, fn func(Match) error) (Stats, error) {
	st := Stats{Carved: map[string]int64{}, Rejected: map[string]int64{}}
	sigs := opt.Signatures
	if len(sigs) == 0 {
		sigs = Signatures
	}
	if opt.Align <= 0 {
		opt.Align = 512
	}
	end := opt.End
	if end <= 0 || end > size {
		end = size
	}
	d := newDispatch(sigs)
	// try validates every signature whose magic matches at buf[i]; it returns
	// the first valid match.
	try := func(buf []byte, i int, pos int64) (Match, bool) {
		for _, o := range d.offsets {
			if i+o >= len(buf) {
				continue
			}
			for _, s := range d.table[dispatchKey{o, buf[i+o]}] {
				mo := i + s.MagicOffset
				if mo+len(s.Magic) > len(buf) || !bytes.Equal(buf[mo:mo+len(s.Magic)], s.Magic) {
					continue
				}
				st.Candidates++
				src := &Src{r: r, off: pos, limit: min(s.MaxSize, size-pos)}
				res, err := s.Validate(src)
				if err != nil || res.Length <= 0 || res.Length > src.limit {
					st.Rejected[s.Name]++
					continue
				}
				if res.Ext == "" {
					res.Ext = s.Ext
				}
				return Match{Offset: pos, Length: res.Length, Type: s.Name, Ext: res.Ext, Validation: res.Validation, Notes: res.Notes}, true
			}
		}
		return Match{}, false
	}

	buf := make([]byte, chunkSize+headroom)
	next := alignUp(opt.Start, opt.Align)
	for base := next; base < end; base += chunkSize {
		if err := ctx.Err(); err != nil {
			return st, err
		}
		n, rerr := readTolerant(r, buf[:min(int64(len(buf)), size-base)], base)
		st.ReadErrors += rerr
		limit := min(int64(chunkSize), end-base, int64(n))
		for i := int64(0); i < limit; i++ {
			pos := base + i
			if pos < next {
				i = next - base - 1
				continue
			}
			if pos%opt.Align != 0 {
				i += opt.Align - pos%opt.Align - 1
				continue
			}
			m, ok := try(buf[:n], int(i), pos)
			if !ok || m.Length < opt.MinSize {
				continue
			}
			if err := fn(m); err != nil {
				return st, err
			}
			st.Carved[m.Type]++
			if !opt.NoSkip {
				next = alignUp(pos+m.Length, opt.Align)
			}
		}
		st.Scanned = min(base+chunkSize, end) - alignUp(opt.Start, opt.Align)
		if opt.Progress != nil {
			opt.Progress(min(base+chunkSize, end))
		}
	}
	return st, nil
}

type dispatchKey struct {
	off int
	b   byte
}

// dispatch indexes signatures by (magic offset, first magic byte) so each
// position costs one map lookup per distinct magic offset.
type dispatch struct {
	table   map[dispatchKey][]*Signature
	offsets []int
}

func newDispatch(sigs []*Signature) dispatch {
	d := dispatch{table: map[dispatchKey][]*Signature{}}
	seen := map[int]bool{}
	for _, s := range sigs {
		k := dispatchKey{s.MagicOffset, s.Magic[0]}
		d.table[k] = append(d.table[k], s)
		if !seen[s.MagicOffset] {
			seen[s.MagicOffset] = true
			d.offsets = append(d.offsets, s.MagicOffset)
		}
	}
	sort.Ints(d.offsets)
	return d
}

func alignUp(v, a int64) int64 {
	if r := v % a; r != 0 {
		return v + a - r
	}
	return v
}

// readTolerant fills p from r at off. On a read error it retries sector by
// sector, zero-filling unreadable sectors, so one bad sector does not hide a
// whole chunk from the scanner. It returns the bytes available and the
// number of unreadable sectors.
func readTolerant(r io.ReaderAt, p []byte, off int64) (int, int64) {
	n, err := r.ReadAt(p, off)
	if err == nil || n == len(p) || errors.Is(err, io.EOF) {
		return n, 0
	}
	var bad int64
	const ss = 512
	for i := n - n%ss; i < len(p); i += ss {
		end := min(i+ss, len(p))
		k, err := r.ReadAt(p[i:end], off+int64(i))
		if errors.Is(err, io.EOF) {
			return i + k, bad
		}
		if err != nil && k < end-i {
			clear(p[i:end])
			bad++
		}
	}
	return len(p), bad
}
