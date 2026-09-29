package ntfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"time"

	"github.com/shanurwan/barerelic/internal/extent"
)

const (
	recordMFT     = 0
	recordBitmap  = 6
	recordRoot    = 5
	firstUserRec  = 24
	maxRecords    = 1 << 32
	maxBitmapSize = 1 << 30
	maxPathDepth  = 256
)

// Volume is an opened NTFS volume. Offsets are volume-relative.
type Volume struct {
	r        io.ReaderAt
	size     int64
	Boot     *BootSector
	mftRuns  []Run
	mftSize  int64
	bitmap   []byte
	Warnings []string
}

// Open reads the boot sector (falling back to the backup at the end of the
// volume), locates the MFT via record 0 (falling back to $MFTMirr) and loads
// the cluster allocation bitmap.
func Open(r io.ReaderAt, size int64) (*Volume, error) {
	v := &Volume{r: r, size: size}
	sec := make([]byte, 512)
	if _, err := r.ReadAt(sec, 0); err != nil {
		return nil, fmt.Errorf("ntfs: read boot sector: %w", err)
	}
	bs, err := ParseBootSector(sec)
	if err != nil {
		for _, ss := range []int64{512, 4096} {
			if size < ss {
				continue
			}
			if _, rerr := r.ReadAt(sec, size-ss); rerr != nil {
				continue
			}
			if bbs, berr := ParseBootSector(sec); berr == nil {
				v.Warnings = append(v.Warnings, "primary boot sector invalid ("+err.Error()+"); using backup boot sector")
				bs, err = bbs, nil
				break
			}
		}
		if err != nil {
			return nil, err
		}
	}
	v.Boot = bs
	if bs.VolumeSize() > size {
		v.Warnings = append(v.Warnings, fmt.Sprintf("volume declares %d bytes but only %d are available", bs.VolumeSize(), size))
	}
	cs := bs.ClusterSize()

	rec0 := make([]byte, bs.RecordSize)
	var mftRec *Record
	for _, loc := range []struct {
		lcn  uint64
		name string
	}{{bs.MFTCluster, "$MFT"}, {bs.MFTMirrCluster, "$MFTMirr"}} {
		if _, err := r.ReadAt(rec0, int64(loc.lcn)*cs); err != nil {
			v.Warnings = append(v.Warnings, fmt.Sprintf("%s record 0 unreadable: %v", loc.name, err))
			continue
		}
		rec, err := ParseRecord(rec0)
		if err != nil {
			v.Warnings = append(v.Warnings, fmt.Sprintf("%s record 0 invalid: %v", loc.name, err))
			continue
		}
		if loc.name == "$MFTMirr" {
			v.Warnings = append(v.Warnings, "using $MFTMirr to locate the MFT")
		}
		mftRec = rec
		break
	}
	if mftRec == nil {
		return nil, errors.New("ntfs: cannot locate the MFT (record 0 and its mirror are unusable); try `recover --deep` or carving")
	}
	data, ok := unnamedData(mftRec.Attrs)
	if !ok || !data.NonResident {
		return nil, errors.New("ntfs: $MFT has no non-resident $DATA attribute")
	}
	v.mftRuns = data.Runs
	v.mftSize = data.DataSize
	if err := v.extendMFTRuns(mftRec); err != nil {
		v.Warnings = append(v.Warnings, "$MFT attribute list incomplete: "+err.Error())
	}
	// The MFT cannot be larger than the volume holding it; never size the
	// record table from untrusted metadata alone.
	if v.mftSize < 0 || v.mftSize > size || v.mftSize/int64(bs.RecordSize) > maxRecords {
		return nil, fmt.Errorf("ntfs: implausible MFT size %d for a %d-byte volume", v.mftSize, size)
	}

	if err := v.loadBitmap(); err != nil {
		v.Warnings = append(v.Warnings, "cluster bitmap unavailable; reallocation of deleted files cannot be assessed: "+err.Error())
	}
	return v, nil
}

// extendMFTRuns follows $MFT's own $ATTRIBUTE_LIST: a heavily fragmented MFT
// stores later runlist segments in extension records.
func (v *Volume) extendMFTRuns(mft *Record) error {
	var list []byte
	for _, a := range mft.Attrs {
		if a.Type == AttrAttributeList {
			if a.NonResident {
				buf, err := io.ReadAll(io.LimitReader(v.runsReader(a.Runs, a.DataSize, a.InitSize), 1<<20))
				if err != nil {
					return err
				}
				list = buf
			} else {
				list = a.Value
			}
		}
	}
	if list == nil {
		return nil
	}
	seen := map[uint64]bool{0: true}
	var extra []Attr
	for _, ent := range parseAttrList(list) {
		num, _ := Ref(ent.ref)
		if ent.typ != AttrData || seen[num] {
			continue
		}
		seen[num] = true
		rec, err := v.ReadRecord(num)
		if err != nil {
			return fmt.Errorf("extension record %d: %w", num, err)
		}
		for _, a := range rec.Attrs {
			if a.Type == AttrData && a.Name == "" && a.NonResident {
				extra = append(extra, a)
			}
		}
	}
	if len(extra) > 0 {
		v.mftRuns = mergeRuns(append([]Attr{{StartVCN: 0, Runs: v.mftRuns}}, extra...))
	}
	return nil
}

func (v *Volume) loadBitmap() error {
	rec, err := v.ReadRecord(recordBitmap)
	if err != nil {
		return err
	}
	a, ok := unnamedData(rec.Attrs)
	if !ok {
		return errors.New("$Bitmap has no $DATA")
	}
	if a.DataSize > maxBitmapSize || a.DataSize > v.size {
		return fmt.Errorf("$Bitmap of %d bytes is implausible", a.DataSize)
	}
	if !a.NonResident {
		v.bitmap = a.Value
		return nil
	}
	buf := make([]byte, a.DataSize)
	if _, err := io.ReadFull(v.runsReader(a.Runs, a.DataSize, a.InitSize), buf); err != nil {
		return err
	}
	v.bitmap = buf
	return nil
}

// RecordCount returns the number of records the MFT can hold.
func (v *Volume) RecordCount() uint64 { return uint64(v.mftSize / int64(v.Boot.RecordSize)) }

// recordOffset maps record n to its volume offset (-1 if unmapped).
func (v *Volume) recordOffset(n uint64) int64 {
	cs := v.Boot.ClusterSize()
	off := int64(n) * int64(v.Boot.RecordSize)
	vcn := off / cs
	for _, r := range v.mftRuns {
		if vcn >= r.VCN && vcn < r.VCN+r.Length && r.LCN >= 0 {
			return (r.LCN+vcn-r.VCN)*cs + off%cs
		}
	}
	return -1
}

// ReadRecord reads and parses MFT record n.
func (v *Volume) ReadRecord(n uint64) (*Record, error) {
	buf := make([]byte, v.Boot.RecordSize)
	if _, err := v.readVirtual(v.mftRuns, buf, int64(n)*int64(v.Boot.RecordSize)); err != nil {
		return nil, fmt.Errorf("ntfs: record %d: %w", n, err)
	}
	return ParseRecord(buf)
}

// readVirtual reads virtual bytes of a non-resident stream described by runs.
func (v *Volume) readVirtual(runs []Run, p []byte, off int64) (int, error) {
	cs := v.Boot.ClusterSize()
	done := 0
	for done < len(p) {
		pos := off + int64(done)
		vcn := pos / cs
		idx := sort.Search(len(runs), func(i int) bool { return runs[i].VCN+runs[i].Length > vcn })
		if idx == len(runs) || runs[idx].VCN > vcn {
			return done, io.EOF
		}
		r := runs[idx]
		within := (vcn-r.VCN)*cs + pos%cs
		n := int(min(int64(len(p)-done), r.Length*cs-within))
		if r.LCN < 0 {
			clear(p[done : done+n])
		} else if _, err := v.r.ReadAt(p[done:done+n], r.LCN*cs+within); err != nil {
			return done, err
		}
		done += n
	}
	return done, nil
}

func (v *Volume) runsReader(runs []Run, dataSize, initSize int64) io.Reader {
	return runsExtents(runs, v.Boot.ClusterSize(), dataSize, initSize).Reader(v.r)
}

// runsExtents converts runs into byte extents. Bytes past the initialized
// size are defined to read as zeros and are emitted as sparse extents.
func runsExtents(runs []Run, cs, dataSize, initSize int64) extent.List {
	var l extent.List
	for _, r := range runs {
		if r.LCN < 0 {
			l = l.Append(extent.Extent{Offset: -1, Length: r.Length * cs})
		} else {
			l = l.Append(extent.Extent{Offset: r.LCN * cs, Length: r.Length * cs})
		}
	}
	initSize = min(initSize, dataSize)
	l = l.Truncate(initSize)
	if got := l.Total(); got < dataSize {
		l = l.Append(extent.Extent{Offset: -1, Length: dataSize - got})
	}
	return l
}

// ClusterAllocated reports whether a cluster is marked in use in $Bitmap.
func (v *Volume) ClusterAllocated(lcn int64) (allocated, known bool) {
	if v.bitmap == nil || lcn < 0 || lcn/8 >= int64(len(v.bitmap)) {
		return false, false
	}
	return v.bitmap[lcn/8]&(1<<(lcn%8)) != 0, true
}

func unnamedData(attrs []Attr) (Attr, bool) {
	for _, a := range attrs {
		if a.Type == AttrData && a.Name == "" && a.StartVCN == 0 {
			return a, true
		}
	}
	return Attr{}, false
}

type attrListEntry struct {
	typ      uint32
	startVCN int64
	ref      uint64
	name     string
}

func parseAttrList(b []byte) []attrListEntry {
	var out []attrListEntry
	for pos := 0; pos+26 <= len(b) && len(out) < 4096; {
		l := int(binary.LittleEndian.Uint16(b[pos+4:]))
		if l < 26 || pos+l > len(b) {
			break
		}
		e := attrListEntry{
			typ:      binary.LittleEndian.Uint32(b[pos:]),
			startVCN: int64(binary.LittleEndian.Uint64(b[pos+8:])),
			ref:      binary.LittleEndian.Uint64(b[pos+16:]),
		}
		if nl, no := int(b[pos+6]), int(b[pos+7]); nl > 0 && pos+no+2*nl <= pos+l {
			e.name = decodeUTF16(b[pos+no : pos+no+2*nl])
		}
		out = append(out, e)
		pos += l
	}
	return out
}

// mergeRuns concatenates runlist segments of one attribute ordered by VCN.
func mergeRuns(segs []Attr) []Run {
	sort.SliceStable(segs, func(i, j int) bool { return segs[i].StartVCN < segs[j].StartVCN })
	var out []Run
	for _, s := range segs {
		out = append(out, s.Runs...)
	}
	return out
}

// Stream is one $DATA stream (the unnamed default stream or an ADS).
type Stream struct {
	Name       string
	Size       int64
	InitSize   int64
	Resident   bool
	Data       []byte // resident content
	DataOffset int64  // volume offset of resident content (provenance only)
	Runs       []Run
	Compressed bool
	Encrypted  bool
	Sparse     bool
}

// File is a recoverable file described by an MFT record.
type File struct {
	Record       uint64
	Sequence     uint16
	RecordOffset int64
	Path         string
	Name         string
	Dir          bool
	Deleted      bool
	Orphan       bool // parent chain could not be resolved
	OutsideMFT   bool // found by deep scan outside the current MFT
	Created      time.Time
	Modified     time.Time
	Accessed     time.Time
	MFTChange    time.Time
	Streams      []Stream
	Notes        []string
}

// Scope selects which records Walk reports.
type Scope int

const (
	ScopeDeleted Scope = iota // only records whose in-use flag is clear
	ScopeAll                  // live and deleted
)

// WalkOptions control traversal.
type WalkOptions struct {
	Scope         Scope
	IncludeSystem bool // include metafiles ($MFT, $LogFile, $Extend/...)
	// Deep also scans the whole volume for FILE records outside the current
	// MFT, e.g. the MFT of a previous installation left behind by a format.
	Deep bool
}

type node struct {
	valid   bool
	inUse   bool
	dir     bool
	seq     uint16
	base    uint64
	parent  uint64
	name    string
	hasName bool
}

// Walk reports files matching opt. It streams the MFT twice: once to build
// the directory tree, once to decode and report files, keeping memory
// proportional to the number of records rather than their content.
func (v *Volume) Walk(ctx context.Context, opt WalkOptions, fn func(File) error) error {
	count := v.RecordCount()
	nodes := make([]node, count)
	ext := map[uint64][]uint64{}
	bad := 0
	for i := uint64(0); i < count; i++ {
		if i%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		rec, err := v.ReadRecord(i)
		if err != nil {
			if !errors.Is(err, ErrNotRecord) {
				bad++
			}
			continue
		}
		n := node{valid: true, inUse: rec.InUse(), dir: rec.IsDir(), seq: rec.Sequence, base: rec.BaseRef}
		if base, _ := Ref(rec.BaseRef); rec.BaseRef != 0 {
			ext[base] = append(ext[base], i)
		}
		if fn, ok := preferredName(fileNames(rec)); ok {
			n.parent, n.name, n.hasName = fn.Parent, fn.Name, true
		}
		nodes[i] = n
	}
	if bad > 0 {
		v.Warnings = append(v.Warnings, fmt.Sprintf("%d MFT records failed validation (torn writes or damaged sectors)", bad))
	}

	pr := &pathResolver{nodes: nodes, cache: map[uint64]resolved{}}
	for i := uint64(0); i < count; i++ {
		if i%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		n := nodes[i]
		if !n.valid || !n.hasName || n.base != 0 || n.dir {
			continue
		}
		if opt.Scope == ScopeDeleted && n.inUse {
			continue
		}
		if !opt.IncludeSystem && i < firstUserRec {
			continue
		}
		rec, err := v.ReadRecord(i)
		if err != nil {
			continue
		}
		f := v.buildFile(i, rec, nodes, ext)
		dir, ok := pr.dirPath(n.parent, 0)
		if !ok {
			f.Orphan = true
			dir = "/$OrphanFiles"
			f.Notes = append(f.Notes, "parent directory record was reused or destroyed; original path unknown")
		}
		f.Path = path.Join("/", dir, f.Name)
		if !opt.IncludeSystem && (f.Path == "/$Extend" || len(f.Path) > 8 && f.Path[:9] == "/$Extend/") {
			continue
		}
		if err := fn(f); err != nil {
			return err
		}
	}
	if opt.Deep {
		return v.scanOrphanRecords(ctx, opt, fn)
	}
	return nil
}

func fileNames(rec *Record) []FileName {
	var out []FileName
	for _, a := range rec.Attrs {
		if a.Type == AttrFileName && !a.NonResident {
			if fn, err := ParseFileName(a.Value); err == nil {
				out = append(out, fn)
			}
		}
	}
	return out
}

// seqMatches accepts a reference whose sequence number equals the record's,
// or is one less when the record is free: NTFS increments the sequence
// number when a record is deleted, so a deleted child still points at its
// deleted parent's previous sequence.
func seqMatches(n node, seq uint16) bool {
	return seq == 0 || n.seq == seq || (!n.inUse && n.seq == seq+1)
}

type resolved struct {
	path string
	ok   bool
}

type pathResolver struct {
	nodes []node
	cache map[uint64]resolved
}

func (p *pathResolver) dirPath(ref uint64, depth int) (string, bool) {
	num, seq := Ref(ref)
	if num == recordRoot {
		return "/", true
	}
	if depth > maxPathDepth || num >= uint64(len(p.nodes)) {
		return "", false
	}
	n := p.nodes[num]
	if !n.valid || !n.hasName || !n.dir || !seqMatches(n, seq) {
		return "", false
	}
	if r, hit := p.cache[num]; hit {
		return r.path, r.ok
	}
	p.cache[num] = resolved{} // cycle guard: a loop resolves as unresolvable
	parent, ok := p.dirPath(n.parent, depth+1)
	r := resolved{path: path.Join(parent, n.name), ok: ok}
	p.cache[num] = r
	return r.path, r.ok
}

// buildFile decodes a base record plus its extension records.
func (v *Volume) buildFile(num uint64, rec *Record, nodes []node, ext map[uint64][]uint64) File {
	f := File{
		Record:       num,
		Sequence:     rec.Sequence,
		RecordOffset: v.recordOffset(num),
		Dir:          rec.IsDir(),
		Deleted:      !rec.InUse(),
	}
	attrs := append([]Attr(nil), rec.Attrs...)
	attrOffsets := make([]int64, len(attrs))
	for i := range attrOffsets {
		attrOffsets[i] = f.RecordOffset
	}
	for _, e := range ext[num] {
		n := nodes[e]
		if !seqMatches(node{seq: rec.Sequence, inUse: rec.InUse()}, uint16(n.base>>48)) {
			continue
		}
		er, err := v.ReadRecord(e)
		if err != nil {
			f.Notes = append(f.Notes, fmt.Sprintf("extension record %d unreadable: %v", e, err))
			continue
		}
		for _, a := range er.Attrs {
			attrs = append(attrs, a)
			attrOffsets = append(attrOffsets, v.recordOffset(e))
		}
	}
	fn, _ := preferredName(fileNames(&Record{Attrs: attrs}))
	f.Name = fn.Name
	f.Created, f.Modified, f.Accessed, f.MFTChange = fn.Created, fn.Modified, fn.Accessed, fn.MFTChange
	for _, a := range attrs {
		if a.Type == AttrStandardInformation && !a.NonResident {
			if si, ok := parseStdInfo(a.Value); ok {
				f.Created, f.Modified, f.Accessed, f.MFTChange = si.Created, si.Modified, si.Accessed, si.MFTChange
			}
		}
	}
	f.Streams = collectStreams(attrs, attrOffsets)
	for _, a := range attrs {
		if a.Type == AttrAttributeList && len(ext[num]) == 0 {
			f.Notes = append(f.Notes, "attribute list present but extension records not found; streams may be incomplete")
			break
		}
	}
	return f
}

func collectStreams(attrs []Attr, recOffsets []int64) []Stream {
	byName := map[string][]Attr{}
	resident := map[string]Stream{}
	var order []string
	for i, a := range attrs {
		if a.Type != AttrData {
			continue
		}
		if _, seen := byName[a.Name]; !seen {
			if _, seen := resident[a.Name]; !seen {
				order = append(order, a.Name)
			}
		}
		if !a.NonResident {
			resident[a.Name] = Stream{Name: a.Name, Size: int64(len(a.Value)), InitSize: int64(len(a.Value)), Resident: true,
				Data: a.Value, DataOffset: recOffsets[i] + int64(a.ValueOffset)}
			continue
		}
		byName[a.Name] = append(byName[a.Name], a)
	}
	var out []Stream
	for _, name := range order {
		if s, ok := resident[name]; ok {
			out = append(out, s)
			continue
		}
		segs := byName[name]
		first := segs[0]
		for _, s := range segs {
			if s.StartVCN == 0 {
				first = s
			}
		}
		out = append(out, Stream{
			Name:       name,
			Size:       first.DataSize,
			InitSize:   first.InitSize,
			Runs:       mergeRuns(segs),
			Compressed: first.Flags&AttrFlagCompressed != 0 && first.CompressionUnit != 0,
			Encrypted:  first.Flags&AttrFlagEncrypted != 0,
			Sparse:     first.Flags&AttrFlagSparse != 0,
		})
	}
	return out
}

// Confidence grades.
const (
	ConfHigh   = "high"
	ConfMedium = "medium"
	ConfLow    = "low"
)

// Plan describes how to read one stream.
type Plan struct {
	Extents     extent.List // volume-relative; for resident data, provenance only
	Data        []byte      // resident content
	Recoverable bool
	Confidence  string
	Notes       []string
}

// PlanStream decides how to read s and how much to trust it.
func (v *Volume) PlanStream(f File, s Stream) Plan {
	p := v.planStream(f, s)
	// A record from outside the current MFT belongs to an earlier file system
	// whose geometry is assumed, not known.
	if f.OutsideMFT && p.Confidence == ConfHigh {
		p.Confidence = ConfMedium
	}
	return p
}

func (v *Volume) planStream(f File, s Stream) Plan {
	if s.Resident {
		return Plan{Data: s.Data, Recoverable: true, Confidence: ConfHigh,
			Extents: extent.List{{Offset: s.DataOffset, Length: int64(len(s.Data))}},
			Notes:   []string{"resident data read from the MFT record (fixups applied)"}}
	}
	if s.Compressed {
		return Plan{Confidence: ConfLow, Notes: []string{"NTFS-compressed (LZNT1) stream; decompression not supported — carve or mount a copy"}}
	}
	if s.Encrypted {
		return Plan{Confidence: ConfLow, Notes: []string{"EFS-encrypted stream; ciphertext cannot be decrypted without the user's keys"}}
	}
	cs := v.Boot.ClusterSize()
	var mapped int64
	for _, r := range s.Runs {
		mapped += r.Length * cs
	}
	p := Plan{Recoverable: true, Confidence: ConfHigh, Extents: runsExtents(s.Runs, cs, s.Size, s.InitSize)}
	if mapped < min(s.InitSize, s.Size) {
		p.Confidence = ConfMedium
		p.Notes = append(p.Notes, fmt.Sprintf("runlist maps %d bytes of %d; tail filled with zeros", mapped, s.Size))
	}
	if f.Deleted {
		var total, realloc int64
		known := true
		for _, r := range s.Runs {
			if r.LCN < 0 {
				continue
			}
			for c := r.LCN; c < r.LCN+r.Length; c++ {
				total++
				a, k := v.ClusterAllocated(c)
				known = known && k
				if a {
					realloc++
				}
			}
		}
		switch {
		case !known:
			p.Confidence = ConfMedium
			p.Notes = append(p.Notes, "cluster allocation unknown; content may have been overwritten")
		case realloc > 0:
			p.Confidence = ConfLow
			p.Notes = append(p.Notes, fmt.Sprintf("%d of %d clusters are now allocated to other data; content is likely partly overwritten", realloc, total))
		}
	}
	if end := p.Extents.Physical(); len(end) > 0 {
		last := end[len(end)-1]
		if last.Offset+last.Length > v.size {
			p.Confidence = ConfLow
			p.Notes = append(p.Notes, "runlist points past the end of the available volume")
		}
	}
	return p
}

// Reader returns the content described by p.
func (v *Volume) Reader(p Plan) io.Reader {
	if p.Data != nil {
		return bytes.NewReader(p.Data)
	}
	return p.Extents.Reader(v.r)
}
