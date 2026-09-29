package fat

import (
	"context"
	"encoding/binary"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	attrReadOnly  = 0x01
	attrHidden    = 0x02
	attrSystem    = 0x04
	attrVolumeID  = 0x08
	attrDirectory = 0x10
	attrLFN       = 0x0F

	deletedMarker = 0xE5

	maxDirBytes       = 65536 * 32 // the FAT specification's 65,536-entry directory limit
	maxDeletedDirSpan = 64
	maxDepth          = 64
	orphanRoot        = "$OrphanDirs"
)

// Entry is a file or directory found on the volume.
type Entry struct {
	Path      string // slash-separated, rooted at "/"
	Name      string // long name when available, else 8.3
	ShortName string
	Dir       bool
	Deleted   bool // this entry, or an ancestor directory, is deleted
	Orphan    bool // found by deep scan, not reachable from the root
	Attr      byte
	Size      uint32
	Cluster   uint32
	Modified  time.Time
	Created   time.Time
	// EntryOffset is the volume-relative offset of the 8.3 directory entry.
	EntryOffset int64
	Notes       []string
}

// WalkOptions control directory traversal.
type WalkOptions struct {
	// Deep additionally scans every cluster of the data area for orphaned
	// directory clusters (subdirectories whose parent was destroyed, e.g. by
	// a quick format that rewrote the root directory and FAT).
	Deep bool
}

type dirJob struct {
	path    string
	cluster uint32 // 0 = FAT12/16 fixed root
	deleted bool
	orphan  bool
	depth   int
}

// Walk visits every entry reachable from the root (live and deleted) and, in
// deep mode, entries in orphaned directories. Directories are visited before
// their contents. fn may return an error to stop the walk.
func (v *Volume) Walk(ctx context.Context, opt WalkOptions, fn func(Entry) error) error {
	visited := map[uint32]bool{}
	var queue []dirJob
	root := dirJob{path: "/"}
	if v.BS.Type == FAT32 {
		root.cluster = v.BS.RootCluster
	}
	queue = append(queue, root)
	if err := v.drain(ctx, &queue, visited, fn); err != nil {
		return err
	}
	if !opt.Deep {
		return nil
	}
	orphans, err := v.findOrphanDirs(ctx, visited)
	if err != nil {
		return err
	}
	for _, c := range orphans {
		if visited[c] {
			continue // reached through another orphan
		}
		queue = append(queue, dirJob{path: path.Join("/", orphanRoot, fmt.Sprintf("dir_%d", c)), cluster: c, deleted: true, orphan: true})
		if err := v.drain(ctx, &queue, visited, fn); err != nil {
			return err
		}
	}
	return nil
}

func (v *Volume) drain(ctx context.Context, queue *[]dirJob, visited map[uint32]bool, fn func(Entry) error) error {
	for len(*queue) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		job := (*queue)[0]
		*queue = (*queue)[1:]
		if job.cluster != 0 {
			if visited[job.cluster] {
				continue
			}
			visited[job.cluster] = true
		}
		buf, offsets, note := v.readDir(job)
		if note != "" {
			v.Warnings = append(v.Warnings, fmt.Sprintf("directory %s: %s", job.path, note))
		}
		for _, e := range v.parseDir(buf, offsets, job) {
			if err := fn(e); err != nil {
				return err
			}
			if e.Dir && v.validCluster(e.Cluster) && !visited[e.Cluster] {
				if job.depth+1 >= maxDepth {
					v.Warnings = append(v.Warnings, fmt.Sprintf("directory %s exceeds depth %d; not descended", e.Path, maxDepth))
					continue
				}
				*queue = append(*queue, dirJob{path: e.Path, cluster: e.Cluster, deleted: e.Deleted, orphan: job.orphan, depth: job.depth + 1})
			}
		}
	}
	return nil
}

// readDir returns the raw directory bytes and the volume offset of each
// cluster (or of the fixed root region) so entry offsets can be reported.
func (v *Volume) readDir(job dirJob) ([]byte, []int64, string) {
	if job.cluster == 0 {
		off := int64(v.BS.ReservedSectors+v.BS.NumFATs*v.BS.FATSize) * int64(v.BS.BytesPerSector)
		buf := make([]byte, int64(v.BS.RootEntries)*32)
		if _, err := v.r.ReadAt(buf, off); err != nil {
			return nil, nil, "root directory unreadable: " + err.Error()
		}
		return buf, []int64{off}, ""
	}
	var clusters []uint32
	var note string
	if job.deleted && v.entry(job.cluster) == 0 {
		// Chain erased: take the first cluster plus following free clusters
		// that still look like directory data.
		clusters = []uint32{job.cluster}
		for c := job.cluster + 1; v.validCluster(c) && len(clusters) < maxDeletedDirSpan && !v.Allocated(c); c++ {
			b := make([]byte, v.ClusterSize())
			if _, err := v.r.ReadAt(b, v.ClusterOffset(c)); err != nil || !looksLikeDirData(b) {
				break
			}
			clusters = append(clusters, c)
		}
	} else {
		clusters, note = v.chain(job.cluster, int(max(1, maxDirBytes/v.ClusterSize())))
		seen := make(map[uint32]bool, len(clusters))
		for i, c := range clusters {
			if seen[c] {
				clusters, note = clusters[:i], fmt.Sprintf("cluster chain loops back to cluster %d", c)
				break
			}
			seen[c] = true
		}
	}
	cs := v.ClusterSize()
	buf := make([]byte, int64(len(clusters))*cs)
	offs := make([]int64, len(clusters))
	for i, c := range clusters {
		offs[i] = v.ClusterOffset(c)
		if _, err := v.r.ReadAt(buf[int64(i)*cs:int64(i+1)*cs], offs[i]); err != nil {
			return buf[:int64(i)*cs], offs[:i], fmt.Sprintf("cluster %d unreadable: %v", c, err)
		}
	}
	if job.deleted && len(buf) >= 64 && !isDotEntry(buf[0:32], ".") {
		return nil, nil, "deleted directory's first cluster no longer holds a directory (overwritten)"
	}
	return buf, offs, note
}

type lfnPart struct {
	ord   byte
	sum   byte
	chars []uint16
}

func (v *Volume) parseDir(buf []byte, offs []int64, job dirJob) []Entry {
	var out []Entry
	var lfn []lfnPart
	chunk := int64(len(buf))
	if len(offs) > 1 || job.cluster != 0 {
		chunk = v.ClusterSize()
	}
	for i := 0; i+32 <= len(buf); i += 32 {
		e := buf[i : i+32]
		if e[0] == 0x00 {
			break // end-of-directory marker
		}
		attr := e[11]
		if attr == attrLFN {
			lfn = append(lfn, lfnPart{ord: e[0], sum: e[13], chars: lfnChars(e)})
			continue
		}
		parts := lfn
		lfn = nil
		if attr&0xC0 != 0 || (attr&attrVolumeID != 0 && attr&attrDirectory == 0) {
			continue // reserved bits or volume label
		}
		if isDotEntry(e, ".") || isDotEntry(e, "..") {
			continue
		}
		deleted := e[0] == deletedMarker
		if !validShortName(e[:11], deleted) {
			continue
		}
		long, first, lfnNote := assembleLFN(parts, e[:11], deleted)
		short := shortName(e, first)
		name := short
		if long != "" {
			name = long
		}
		ent := Entry{
			Path:      path.Join(job.path, name),
			Name:      name,
			ShortName: short,
			Dir:       attr&attrDirectory != 0,
			Deleted:   deleted || job.deleted,
			Orphan:    job.orphan,
			Attr:      attr,
			Size:      binary.LittleEndian.Uint32(e[28:]),
			Cluster:   uint32(binary.LittleEndian.Uint16(e[26:])),
			Modified:  fatTime(binary.LittleEndian.Uint16(e[24:]), binary.LittleEndian.Uint16(e[22:]), 0),
			Created:   fatTime(binary.LittleEndian.Uint16(e[16:]), binary.LittleEndian.Uint16(e[14:]), e[13]),
		}
		if v.BS.Type == FAT32 {
			ent.Cluster |= uint32(binary.LittleEndian.Uint16(e[20:])) << 16
		}
		if ci := int64(i) / chunk; ci < int64(len(offs)) {
			ent.EntryOffset = offs[ci] + int64(i)%chunk
		}
		if lfnNote != "" {
			ent.Notes = append(ent.Notes, lfnNote)
		}
		if deleted && first == 0 {
			ent.Notes = append(ent.Notes, "first character of 8.3 name erased by deletion; shown as '_'")
		}
		if ent.Dir {
			ent.Size = 0
		}
		out = append(out, ent)
	}
	return out
}

func lfnChars(e []byte) []uint16 {
	var u []uint16
	for _, r := range [][2]int{{1, 11}, {14, 26}, {28, 32}} {
		for j := r[0]; j < r[1]; j += 2 {
			u = append(u, binary.LittleEndian.Uint16(e[j:]))
		}
	}
	return u
}

// ShortNameChecksum is the LFN checksum of an 11-byte 8.3 name.
func ShortNameChecksum(name []byte) byte {
	var sum byte
	for _, c := range name[:11] {
		sum = (sum&1)<<7 + sum>>1 + c
	}
	return sum
}

// likelyFirstChars are tried first when reconstructing an erased first byte.
const likelyFirstChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$~!#%&'()-@^`{}"

// assembleLFN validates LFN parts against their 8.3 entry and returns the
// long name. For deleted entries the first byte of the 8.3 name is gone; it
// is recovered by finding the byte whose checksum matches the LFN checksum.
func assembleLFN(parts []lfnPart, sfn []byte, deleted bool) (name string, first byte, note string) {
	if !deleted {
		first = sfn[0]
		if first == 0x05 {
			first = 0xE5
		}
	}
	if len(parts) == 0 {
		return "", first, ""
	}
	sum := parts[0].sum
	for _, p := range parts {
		if p.sum != sum {
			return "", first, "long-name fragments disagree; long name discarded"
		}
	}
	if deleted {
		cand := append([]byte(nil), sfn[:11]...)
		found := false
		try := func(c byte) bool {
			cand[0] = c
			return ShortNameChecksum(cand) == sum
		}
		for i := 0; i < len(likelyFirstChars) && !found; i++ {
			if try(likelyFirstChars[i]) {
				first, found = likelyFirstChars[i], true
			}
		}
		for c := 0x20; c < 0x100 && !found; c++ {
			if c != deletedMarker && try(byte(c)) {
				first, found = byte(c), true
			}
		}
		if !found {
			return "", 0, "orphaned long-name fragments (checksum mismatch); long name discarded"
		}
	} else {
		if ShortNameChecksum(sfn) != sum {
			return "", first, "long-name checksum mismatch; long name discarded"
		}
		for k, p := range parts {
			want := byte(len(parts) - k)
			if p.ord&0x1F != want || (k == 0) != (p.ord&0x40 != 0) {
				return "", first, "long-name sequence broken; long name discarded"
			}
		}
	}
	var u []uint16
	for k := len(parts) - 1; k >= 0; k-- {
		u = append(u, parts[k].chars...)
	}
	for i, c := range u {
		if c == 0x0000 {
			u = u[:i]
			break
		}
	}
	for len(u) > 0 && u[len(u)-1] == 0xFFFF {
		u = u[:len(u)-1]
	}
	name = string(utf16.Decode(u))
	if strings.TrimSpace(name) == "" {
		return "", first, ""
	}
	return name, first, ""
}

const invalidShortChars = "\"*+,./:;<=>?[\\]|"

func validShortName(n []byte, deleted bool) bool {
	start := 0
	if deleted {
		start = 1
	} else if n[0] == ' ' {
		return false
	}
	for _, c := range n[start:11] {
		if c < 0x20 || strings.IndexByte(invalidShortChars, c) >= 0 {
			return false
		}
	}
	return true
}

func isDotEntry(e []byte, dot string) bool {
	want := dot + strings.Repeat(" ", 11-len(dot))
	return string(e[:11]) == want && e[11]&attrDirectory != 0
}

// shortName decodes an 8.3 name, applying the NT lowercase flags.
// first replaces the first byte (0 = unknown, shown as '_').
func shortName(e []byte, first byte) string {
	raw := append([]byte(nil), e[:11]...)
	if first == 0 {
		raw[0] = '_'
	} else {
		raw[0] = first
	}
	base := decodeOEM(strings.TrimRight(string(raw[:8]), " "))
	ext := decodeOEM(strings.TrimRight(string(raw[8:11]), " "))
	if e[12]&0x08 != 0 {
		base = strings.ToLower(base)
	}
	if e[12]&0x10 != 0 {
		ext = strings.ToLower(ext)
	}
	if ext == "" {
		return base
	}
	return base + "." + ext
}

// fatTime decodes FAT local date/time. FAT stores no time zone; the value is
// reported as-is in UTC.
func fatTime(date, tm uint16, tenths byte) time.Time {
	if date == 0 {
		return time.Time{}
	}
	y, mo, d := int(date>>9)+1980, int(date>>5&0x0F), int(date&0x1F)
	h, mi, s := int(tm>>11), int(tm>>5&0x3F), int(tm&0x1F)*2
	if mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59 {
		return time.Time{}
	}
	ns := int(tenths%200) * 10 * int(time.Millisecond)
	return time.Date(y, time.Month(mo), d, h, mi, s, ns, time.UTC)
}

// looksLikeDirData reports whether a cluster plausibly contains directory
// entries (used to extend a deleted directory beyond its first cluster).
func looksLikeDirData(b []byte) bool {
	valid := 0
	for i := 0; i+32 <= len(b); i += 32 {
		e := b[i : i+32]
		if e[0] == 0 {
			return valid > 0
		}
		if e[11] == attrLFN {
			valid++
			continue
		}
		if e[11]&0xC0 != 0 || !validShortName(e[:11], e[0] == deletedMarker) {
			return false
		}
		valid++
	}
	return valid > 0
}

// findOrphanDirs scans the data area for clusters that begin with "." and
// ".." entries but were not reached by the tree walk.
func (v *Volume) findOrphanDirs(ctx context.Context, visited map[uint32]bool) ([]uint32, error) {
	cs := v.ClusterSize()
	perChunk := max(int64(1), (4<<20)/cs)
	buf := make([]byte, perChunk*cs)
	parents := map[uint32]uint32{}
	var found []uint32
	last := v.readableClusters()
	for c := uint32(2); c < last; c += uint32(perChunk) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := min(int64(last-c), perChunk)
		chunk := buf[:n*cs]
		k, _ := v.r.ReadAt(chunk, v.ClusterOffset(c))
		for i := int64(0); i < n && (i+1)*cs <= int64(k); i++ {
			head := chunk[i*cs:]
			cl := c + uint32(i)
			if visited[cl] || !isDotEntry(head[0:32], ".") || !isDotEntry(head[32:64], "..") {
				continue
			}
			found = append(found, cl)
			parent := uint32(binary.LittleEndian.Uint16(head[32+26:]))
			if v.BS.Type == FAT32 {
				parent |= uint32(binary.LittleEndian.Uint16(head[32+20:])) << 16
			}
			parents[cl] = parent
		}
	}
	// Process orphan roots (whose parent is not itself an orphan) first so
	// that nested orphans keep their relative paths.
	isOrphan := map[uint32]bool{}
	for _, c := range found {
		isOrphan[c] = true
	}
	sort.SliceStable(found, func(i, j int) bool {
		return !isOrphan[parents[found[i]]] && isOrphan[parents[found[j]]]
	})
	return found, nil
}
