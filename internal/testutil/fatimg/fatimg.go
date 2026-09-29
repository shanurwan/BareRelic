// Package fatimg builds FAT12/16/32 images in memory for tests. It is written
// from the specification independently of internal/fs/fat so the parser is
// not validated against its own assumptions.
package fatimg

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// Type is the FAT variant.
type Type int

const (
	FAT12 Type = 12
	FAT16 Type = 16
	FAT32 Type = 32
)

const (
	AttrDirectory = 0x10
	AttrArchive   = 0x20
	attrLFN       = 0x0F
	deleted       = 0xE5
)

// Image is a FAT volume under construction.
type Image struct {
	B                                         []byte
	Typ                                       Type
	BPS, SPC, Reserved, NFATs, RootEnt, FATSz uint32
	Total, RootCluster, FirstData             uint32
	next                                      uint32
}

// New formats an empty volume of the given type.
func New(typ Type) *Image {
	b := &Image{Typ: typ, BPS: 512, NFATs: 2}
	switch typ {
	case FAT12:
		b.SPC, b.Reserved, b.RootEnt, b.FATSz, b.Total = 1, 1, 224, 9, 2880
	case FAT16:
		b.SPC, b.Reserved, b.RootEnt, b.FATSz, b.Total = 4, 4, 512, 40, 40000
	case FAT32:
		b.SPC, b.Reserved, b.RootEnt, b.FATSz, b.Total = 1, 32, 0, 520, 32+2*520+66000
		b.RootCluster = 2
	}
	b.B = make([]byte, int(b.Total*b.BPS))
	s := b.B
	s[0], s[1], s[2] = 0xEB, 0x3C, 0x90
	copy(s[3:], "MSDOS5.0")
	binary.LittleEndian.PutUint16(s[11:], uint16(b.BPS))
	s[13] = byte(b.SPC)
	binary.LittleEndian.PutUint16(s[14:], uint16(b.Reserved))
	s[16] = byte(b.NFATs)
	binary.LittleEndian.PutUint16(s[17:], uint16(b.RootEnt))
	s[21] = 0xF8
	if b.Total < 0x10000 && typ != FAT32 {
		binary.LittleEndian.PutUint16(s[19:], uint16(b.Total))
	} else {
		binary.LittleEndian.PutUint32(s[32:], b.Total)
	}
	if typ == FAT32 {
		binary.LittleEndian.PutUint32(s[36:], b.FATSz)
		binary.LittleEndian.PutUint32(s[44:], b.RootCluster)
		binary.LittleEndian.PutUint16(s[50:], 6)
		s[66] = 0x29
		copy(s[71:], "TESTVOL32  ")
	} else {
		binary.LittleEndian.PutUint16(s[22:], uint16(b.FATSz))
		s[38] = 0x29
		copy(s[43:], "TESTVOL    ")
	}
	s[510], s[511] = 0x55, 0xAA
	if typ == FAT32 {
		copy(b.B[6*512:], s[:512]) // backup boot sector
	}
	rootSecs := (b.RootEnt*32 + b.BPS - 1) / b.BPS
	b.FirstData = b.Reserved + b.NFATs*b.FATSz + rootSecs
	b.SetFAT(0, 0x0FFFFFF8)
	b.SetFAT(1, 0x0FFFFFFF)
	b.next = 2
	if typ == FAT32 {
		b.SetFAT(2, 0x0FFFFFFF)
		b.next = 3
	}
	return b
}

// ClusterSize returns the cluster size in bytes.
func (b *Image) ClusterSize() int { return int(b.BPS * b.SPC) }

// ClusterOffset returns the byte offset of cluster c.
func (b *Image) ClusterOffset(c uint32) int { return int((b.FirstData + (c-2)*b.SPC) * b.BPS) }

// SetFAT writes a FAT entry in every FAT copy.
func (b *Image) SetFAT(c, v uint32) {
	for i := uint32(0); i < b.NFATs; i++ {
		f := b.B[(b.Reserved+i*b.FATSz)*b.BPS:]
		switch b.Typ {
		case FAT12:
			o := c * 3 / 2
			x := binary.LittleEndian.Uint16(f[o:])
			if c&1 == 1 {
				x = x&0x000F | uint16(v&0xFFF)<<4
			} else {
				x = x&0xF000 | uint16(v&0xFFF)
			}
			binary.LittleEndian.PutUint16(f[o:], x)
		case FAT16:
			binary.LittleEndian.PutUint16(f[c*2:], uint16(v))
		default:
			binary.LittleEndian.PutUint32(f[c*4:], v&0x0FFFFFFF)
		}
	}
}

// Alloc stores data in consecutive free clusters (leaving a one-cluster hole
// after the first cluster when fragmented) and chains them.
func (b *Image) Alloc(data []byte, fragmented bool) []uint32 {
	n := max(1, (len(data)+b.ClusterSize()-1)/b.ClusterSize())
	var cl []uint32
	for i := 0; i < n; i++ {
		if fragmented && i == 1 {
			b.next++
		}
		cl = append(cl, b.next)
		b.next++
	}
	cs := b.ClusterSize()
	for i, c := range cl {
		if end := min(len(data), (i+1)*cs); i*cs < end {
			copy(b.B[b.ClusterOffset(c):], data[i*cs:end])
		}
		if i+1 < len(cl) {
			b.SetFAT(c, cl[i+1])
		} else {
			b.SetFAT(c, 0x0FFFFFFF)
		}
	}
	return cl
}

// Dir is a directory being filled with entries.
type Dir struct {
	b    *Image
	off  int
	used int
}

// Root returns the root directory.
func (b *Image) Root() *Dir {
	if b.Typ == FAT32 {
		return &Dir{b: b, off: b.ClusterOffset(b.RootCluster)}
	}
	return &Dir{b: b, off: int((b.Reserved + b.NFATs*b.FATSz) * b.BPS)}
}

func shortName(name string) []byte {
	out := []byte("           ")
	base, ext, _ := strings.Cut(strings.ToUpper(name), ".")
	copy(out[:8], base)
	copy(out[8:], ext)
	return out
}

func checksum(n []byte) byte {
	var sum byte
	for _, c := range n[:11] {
		sum = (sum&1)<<7 + sum>>1 + c
	}
	return sum
}

// Add writes optional long-name entries and an 8.3 entry, returning the byte
// offsets of every slot written (for Delete).
func (d *Dir) Add(long, short string, attr byte, cluster, size uint32) []int {
	var offs []int
	s := shortName(short)
	if long != "" {
		u := append(utf16.Encode([]rune(long)), 0)
		for len(u)%13 != 0 {
			u = append(u, 0xFFFF)
		}
		n := len(u) / 13
		sum := checksum(s)
		pos := []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30}
		for k := n; k >= 1; k-- {
			e := d.b.B[d.off+d.used:]
			ord := byte(k)
			if k == n {
				ord |= 0x40
			}
			e[0], e[11], e[13] = ord, attrLFN, sum
			for j, c := range u[(k-1)*13 : k*13] {
				binary.LittleEndian.PutUint16(e[pos[j]:], c)
			}
			offs = append(offs, d.off+d.used)
			d.used += 32
		}
	}
	e := d.b.B[d.off+d.used:]
	copy(e, s)
	e[11] = attr
	binary.LittleEndian.PutUint16(e[20:], uint16(cluster>>16))
	binary.LittleEndian.PutUint16(e[26:], uint16(cluster))
	binary.LittleEndian.PutUint32(e[28:], size)
	binary.LittleEndian.PutUint16(e[24:], (2019-1980)<<9|6<<5|15) // 2019-06-15
	binary.LittleEndian.PutUint16(e[22:], 10<<11|30<<5|8)         // 10:30:16
	offs = append(offs, d.off+d.used)
	d.used += 32
	return offs
}

// Mkdir creates a subdirectory with "." and ".." entries.
func (b *Image) Mkdir(parent *Dir, long, short string, parentCluster uint32) (*Dir, uint32, []int) {
	cl := b.Alloc(make([]byte, b.ClusterSize()), false)[0]
	d := &Dir{b: b, off: b.ClusterOffset(cl)}
	d.Add("", "X", AttrDirectory, cl, 0)
	copy(b.B[d.off:], ".          ")
	d.Add("", "X", AttrDirectory, parentCluster, 0)
	copy(b.B[d.off+32:], "..         ")
	return d, cl, parent.Add(long, short, AttrDirectory, cl, 0)
}

// AddFile allocates data and adds a directory entry for it.
func (b *Image) AddFile(d *Dir, long, short string, data []byte, fragmented bool) ([]uint32, []int) {
	cl := b.Alloc(data, fragmented)
	return cl, d.Add(long, short, AttrArchive, cl[0], uint32(len(data)))
}

// Delete mimics a FAT driver: mark every slot 0xE5 and free the chain.
func (b *Image) Delete(slots []int, clusters []uint32) {
	for _, o := range slots {
		b.B[o] = deleted
	}
	for _, c := range clusters {
		b.SetFAT(c, 0)
	}
}

// QuickFormat zeroes the FATs and fixed root directory (FAT12/16), leaving
// the data area untouched, as a quick format does.
func (b *Image) QuickFormat() {
	clear(b.B[b.Reserved*b.BPS : b.FirstData*b.BPS])
	b.SetFAT(0, 0x0FFFFFF8)
	b.SetFAT(1, 0x0FFFFFFF)
}
