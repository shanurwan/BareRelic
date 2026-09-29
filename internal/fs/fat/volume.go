package fat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/shanurwan/barerelic/internal/extent"
)

// Volume is an opened FAT volume. Offsets are relative to the volume start.
type Volume struct {
	r        io.ReaderAt
	size     int64
	BS       *BootSector
	fat      []byte // raw FAT; decoded on demand to halve memory
	Warnings []string
}

// Open reads the boot sector (falling back to the FAT32 backup boot sector)
// and the first readable FAT copy.
func Open(r io.ReaderAt, size int64) (*Volume, error) {
	sec := make([]byte, 512)
	if _, err := r.ReadAt(sec, 0); err != nil {
		return nil, fmt.Errorf("fat: read boot sector: %w", err)
	}
	v := &Volume{r: r, size: size}
	bs, err := ParseBootSector(sec)
	if err != nil {
		// FAT32 keeps a backup boot sector at sector 6 by convention.
		if _, rerr := r.ReadAt(sec, 6*512); rerr == nil {
			if bbs, berr := ParseBootSector(sec); berr == nil && bbs.Type == FAT32 {
				v.Warnings = append(v.Warnings, "primary boot sector invalid ("+err.Error()+"); using backup boot sector 6")
				bs, err = bbs, nil
			}
		}
		if err != nil {
			return nil, err
		}
	}
	v.BS = bs
	if bs.VolumeSize() > size {
		v.Warnings = append(v.Warnings, fmt.Sprintf("volume declares %d bytes but only %d are available; data past the end is unrecoverable", bs.VolumeSize(), size))
	}

	fatBytes := int64(bs.FATSize) * int64(bs.BytesPerSector)
	if fatBytes > 1<<30 {
		return nil, fmt.Errorf("fat: FAT of %d bytes exceeds the 1 GiB safety limit", fatBytes)
	}
	var readErr error
	for i := uint32(0); i < bs.NumFATs; i++ {
		off := (int64(bs.ReservedSectors) + int64(i)*int64(bs.FATSize)) * int64(bs.BytesPerSector)
		if off+fatBytes > size {
			// Never size allocations from untrusted metadata alone.
			readErr = errors.Join(readErr, fmt.Errorf("FAT copy %d extends past the end of the source", i+1))
			continue
		}
		buf := make([]byte, fatBytes)
		if _, err := r.ReadAt(buf, off); err != nil {
			readErr = errors.Join(readErr, fmt.Errorf("FAT copy %d: %w", i+1, err))
			continue
		}
		if i > 0 {
			v.Warnings = append(v.Warnings, fmt.Sprintf("FAT copy 1 unreadable; using copy %d", i+1))
		}
		v.fat = buf
		break
	}
	if v.fat == nil {
		return nil, fmt.Errorf("fat: no readable FAT: %w", readErr)
	}
	return v, nil
}

// ClusterSize returns the cluster size in bytes.
func (v *Volume) ClusterSize() int64 { return v.BS.ClusterSize() }

func (v *Volume) validCluster(c uint32) bool { return c >= 2 && c < v.BS.ClusterCount+2 }

// readableClusters is the number of clusters (counting the two reserved
// entries) whose data physically lies within the source.
func (v *Volume) readableClusters() uint32 {
	dataStart := int64(v.BS.FirstDataSector) * int64(v.BS.BytesPerSector)
	if v.size <= dataStart {
		return 2
	}
	n := (v.size-dataStart)/v.ClusterSize() + 2
	return uint32(min(n, int64(v.BS.ClusterCount)+2))
}

// ClusterOffset returns the volume-relative byte offset of cluster c.
func (v *Volume) ClusterOffset(c uint32) int64 {
	return int64(v.BS.FirstDataSector)*int64(v.BS.BytesPerSector) + int64(c-2)*v.ClusterSize()
}

// entry decodes the FAT entry for cluster c.
func (v *Volume) entry(c uint32) uint32 {
	switch v.BS.Type {
	case FAT12:
		o := int(c) * 3 / 2
		if o+1 >= len(v.fat) {
			return 0
		}
		x := uint32(binary.LittleEndian.Uint16(v.fat[o:]))
		if c&1 == 1 {
			return x >> 4
		}
		return x & 0x0FFF
	case FAT16:
		o := int(c) * 2
		if o+1 >= len(v.fat) {
			return 0
		}
		return uint32(binary.LittleEndian.Uint16(v.fat[o:]))
	default:
		o := int(c) * 4
		if o+3 >= len(v.fat) {
			return 0
		}
		return binary.LittleEndian.Uint32(v.fat[o:]) & 0x0FFFFFFF
	}
}

func (v *Volume) eocMin() uint32 {
	switch v.BS.Type {
	case FAT12:
		return 0x0FF8
	case FAT16:
		return 0xFFF8
	}
	return 0x0FFFFFF8
}

func (v *Volume) badMarker() uint32 { return v.eocMin() - 1 }

// Allocated reports whether cluster c is currently in use (or marked bad).
func (v *Volume) Allocated(c uint32) bool { return v.entry(c) != 0 }

// chain follows the cluster chain from start, returning at most limit
// clusters. It stops at end-of-chain, free/bad/out-of-range links, cycles
// (detected with Brent's algorithm in O(1) memory) and the limit. A chain
// can never be longer than the number of clusters that physically exist.
func (v *Volume) chain(start uint32, limit int) ([]uint32, string) {
	limit = min(limit, int(v.readableClusters()))
	var out []uint32
	c := start
	tortoise, power, lam := start, 1, 0
	for len(out) < limit {
		if !v.validCluster(c) {
			return out, fmt.Sprintf("chain references invalid cluster %d", c)
		}
		out = append(out, c)
		next := v.entry(c)
		switch {
		case next >= v.eocMin():
			return out, ""
		case next == v.badMarker():
			return out, fmt.Sprintf("chain reaches cluster marked bad after %d", c)
		case next == 0:
			return out, fmt.Sprintf("chain reaches free cluster after %d", c)
		case next == tortoise:
			return trimRepeat(out), fmt.Sprintf("chain loops back to cluster %d", next)
		}
		if lam++; lam == power {
			tortoise, power, lam = next, power*2, 0
		}
		c = next
	}
	return out, ""
}

// trimRepeat cuts a chain at its first repeated cluster (cycle case only).
func trimRepeat(cs []uint32) []uint32 {
	seen := make(map[uint32]bool, len(cs))
	for i, c := range cs {
		if seen[c] {
			return cs[:i]
		}
		seen[c] = true
	}
	return cs
}

func (v *Volume) clustersToExtents(cs []uint32) extent.List {
	var l extent.List
	for _, c := range cs {
		l = l.Append(extent.Extent{Offset: v.ClusterOffset(c), Length: v.ClusterSize()})
	}
	return l
}

// Confidence grades mirror evidence.High/Medium/Low.
const (
	ConfHigh   = "high"
	ConfMedium = "medium"
	ConfLow    = "low"
)

// Plan describes how to read a file's content.
type Plan struct {
	Extents     extent.List // volume-relative
	Recoverable bool
	Confidence  string
	Notes       []string
}

// PlanFile decides which bytes make up e's content.
func (v *Volume) PlanFile(e Entry) Plan {
	size := int64(e.Size)
	if size == 0 {
		return Plan{Recoverable: true, Confidence: ConfHigh}
	}
	if !v.validCluster(e.Cluster) {
		return Plan{Confidence: ConfLow, Notes: []string{fmt.Sprintf("start cluster %d is invalid; content not locatable (use carving)", e.Cluster)}}
	}
	cs := v.ClusterSize()
	need := int((size + cs - 1) / cs)

	if !e.Deleted {
		chain, why := v.chain(e.Cluster, need)
		p := Plan{Recoverable: true, Confidence: ConfHigh}
		if len(chain) < need {
			p.Confidence = ConfMedium
			p.Notes = append(p.Notes, fmt.Sprintf("FAT chain has %d of %d clusters: %s", len(chain), need, why))
		}
		p.Extents = v.clustersToExtents(chain).Truncate(size)
		return p
	}

	// Deleted: the chain is gone; assume contiguity from the start cluster.
	last := min(int64(e.Cluster)+int64(need), int64(v.readableClusters()))
	var cs32 []uint32
	realloc := 0
	for c := e.Cluster; int64(c) < last; c++ {
		cs32 = append(cs32, c)
		if v.Allocated(c) {
			realloc++
		}
	}
	p := Plan{Recoverable: true, Extents: v.clustersToExtents(cs32).Truncate(size)}
	switch {
	case realloc > 0:
		p.Confidence = ConfLow
		p.Notes = append(p.Notes, fmt.Sprintf("%d of %d clusters are now allocated to other data; content is likely partly overwritten", realloc, len(cs32)))
	case need > 1:
		p.Confidence = ConfMedium
		p.Notes = append(p.Notes, "cluster chain erased on deletion; contiguous allocation assumed")
	default:
		p.Confidence = ConfHigh
	}
	if len(cs32) < need {
		p.Notes = append(p.Notes, fmt.Sprintf("only %d of %d clusters lie inside the available volume", len(cs32), need))
		if len(cs32) == 0 {
			p.Recoverable = false
		}
	}
	if v.BS.Type == FAT32 && e.Cluster < 0x10000 && need > 1 {
		p.Notes = append(p.Notes, "FAT32: some systems clear the high word of a deleted entry's start cluster; if content is wrong, carve instead")
	}
	return p
}

// Reader returns the content of a planned file.
func (v *Volume) Reader(p Plan) io.Reader { return p.Extents.Reader(v.r) }
