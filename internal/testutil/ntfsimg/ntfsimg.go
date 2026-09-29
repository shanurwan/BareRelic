// Package ntfsimg builds small NTFS volumes in memory for tests: a boot
// sector (and backup), an MFT with $MFT/$MFTMirr/root/$Bitmap, and arbitrary
// user records. It is written from the on-disk format independently of
// internal/fs/ntfs.
package ntfsimg

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// Geometry of every image built by this package.
const (
	CS       = 4096 // cluster size
	RS       = 1024 // MFT record size
	Records  = 64
	MFTLCN   = 4
	MirrLCN  = 20
	BmpLCN   = 21
	Clusters = 2048
)

// On-disk constants.
const (
	AttrStandardInformation = 0x10
	AttrAttributeList       = 0x20
	AttrFileName            = 0x30
	AttrData                = 0x80
	attrEnd                 = 0xFFFFFFFF

	FlagInUse     = 0x0001
	FlagDirectory = 0x0002
	FlagSparse    = 0x8000

	NSPOSIX    = 0
	NSWin32    = 1
	NSDOS      = 2
	NSWin32DOS = 3

	stride = 512
)

// Time is the timestamp written into every attribute.
var Time = time.Date(2014, 3, 9, 18, 45, 0, 0, time.UTC)

// Root is the MFT reference of the root directory.
var Root = Ref(5, 5)

// Run maps N clusters at LCN; LCN < 0 is sparse.
type Run struct{ LCN, N int64 }

// EncodeRuns produces an NTFS mapping-pairs array.
func EncodeRuns(runs []Run) []byte {
	var out []byte
	prev := int64(0)
	enc := func(v int64, signed bool) []byte {
		var b []byte
		for {
			b = append(b, byte(v))
			v >>= 8
			last := b[len(b)-1]
			if signed && ((v == 0 && last&0x80 == 0) || (v == -1 && last&0x80 != 0)) {
				return b
			}
			if !signed && v == 0 {
				return b
			}
		}
	}
	for _, r := range runs {
		lb := enc(r.N, false)
		var ob []byte
		if r.LCN >= 0 {
			ob = enc(r.LCN-prev, true)
			prev = r.LCN
		}
		out = append(out, byte(len(ob))<<4|byte(len(lb)))
		out = append(out, lb...)
		out = append(out, ob...)
	}
	return append(out, 0)
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func pad8(n int) int { return (n + 7) &^ 7 }

// Resident builds a resident attribute.
func Resident(typ uint32, name string, value []byte) []byte {
	nb := utf16le(name)
	voff := pad8(24 + len(nb))
	b := make([]byte, pad8(voff+len(value)))
	binary.LittleEndian.PutUint32(b[0:], typ)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	b[9] = byte(len(nb) / 2)
	binary.LittleEndian.PutUint16(b[10:], 24)
	copy(b[24:], nb)
	binary.LittleEndian.PutUint32(b[16:], uint32(len(value)))
	binary.LittleEndian.PutUint16(b[20:], uint16(voff))
	copy(b[voff:], value)
	return b
}

// NonResident builds a non-resident attribute.
func NonResident(typ uint32, name string, runs []Run, startVCN, dataSize, initSize int64, flags uint16) []byte {
	nb := utf16le(name)
	rl := EncodeRuns(runs)
	roff := pad8(64 + len(nb))
	b := make([]byte, pad8(roff+len(rl)))
	var clusters int64
	for _, r := range runs {
		clusters += r.N
	}
	binary.LittleEndian.PutUint32(b[0:], typ)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	b[8] = 1
	b[9] = byte(len(nb) / 2)
	binary.LittleEndian.PutUint16(b[10:], 64)
	binary.LittleEndian.PutUint16(b[12:], flags)
	copy(b[64:], nb)
	binary.LittleEndian.PutUint64(b[16:], uint64(startVCN))
	binary.LittleEndian.PutUint64(b[24:], uint64(startVCN+clusters-1))
	binary.LittleEndian.PutUint16(b[32:], uint16(roff))
	binary.LittleEndian.PutUint64(b[40:], uint64(clusters*CS))
	binary.LittleEndian.PutUint64(b[48:], uint64(dataSize))
	binary.LittleEndian.PutUint64(b[56:], uint64(initSize))
	copy(b[roff:], rl)
	return b
}

// Data is a shorthand for a non-resident unnamed $DATA attribute.
func Data(size int64, runs ...Run) []byte {
	return NonResident(AttrData, "", runs, 0, size, size, 0)
}

func filetime(t time.Time) uint64 { return uint64(t.UnixNano()/100) + 116444736000000000 }

// FileName builds a $FILE_NAME attribute.
func FileName(parent uint64, name string, ns byte) []byte {
	nb := utf16le(name)
	v := make([]byte, 66+len(nb))
	binary.LittleEndian.PutUint64(v[0:], parent)
	for o := 8; o <= 32; o += 8 {
		binary.LittleEndian.PutUint64(v[o:], filetime(Time))
	}
	v[64] = byte(len(nb) / 2)
	v[65] = ns
	copy(v[66:], nb)
	return Resident(AttrFileName, "", v)
}

// StdInfo builds $STANDARD_INFORMATION with all four times set to t.
func StdInfo(t time.Time) []byte {
	v := make([]byte, 72)
	for o := 0; o <= 24; o += 8 {
		binary.LittleEndian.PutUint64(v[o:], filetime(t))
	}
	return Resident(AttrStandardInformation, "", v)
}

// AttrList builds $ATTRIBUTE_LIST from {type, startVCN, ref} triples.
func AttrList(entries [][3]uint64) []byte {
	var v []byte
	for _, e := range entries {
		b := make([]byte, 32)
		binary.LittleEndian.PutUint32(b[0:], uint32(e[0]))
		binary.LittleEndian.PutUint16(b[4:], 32)
		b[7] = 26
		binary.LittleEndian.PutUint64(b[8:], e[1])
		binary.LittleEndian.PutUint64(b[16:], e[2])
		v = append(v, b...)
	}
	return Resident(AttrAttributeList, "", v)
}

// Ref builds an MFT reference.
func Ref(num uint64, seq uint16) uint64 { return num | uint64(seq)<<48 }

// Rec describes one MFT record.
type Rec struct {
	Num   uint64
	Seq   uint16
	Flags uint16
	Base  uint64
	Attrs [][]byte
}

// Record serialises a record and applies update-sequence protection.
func Record(s Rec) []byte {
	b := make([]byte, RS)
	copy(b, "FILE")
	usaCount := RS/stride + 1
	binary.LittleEndian.PutUint16(b[4:], 0x30)
	binary.LittleEndian.PutUint16(b[6:], uint16(usaCount))
	binary.LittleEndian.PutUint16(b[0x10:], s.Seq)
	binary.LittleEndian.PutUint16(b[0x12:], 1)
	binary.LittleEndian.PutUint16(b[0x14:], 0x38)
	binary.LittleEndian.PutUint16(b[0x16:], s.Flags)
	binary.LittleEndian.PutUint32(b[0x1C:], RS)
	binary.LittleEndian.PutUint64(b[0x20:], s.Base)
	binary.LittleEndian.PutUint32(b[0x2C:], uint32(s.Num))
	pos := 0x38
	for _, a := range s.Attrs {
		copy(b[pos:], a)
		pos += len(a)
	}
	if pos+8 > RS-2 {
		panic("ntfsimg: record overflow")
	}
	binary.LittleEndian.PutUint32(b[pos:], attrEnd)
	binary.LittleEndian.PutUint32(b[0x18:], uint32(pos+8))
	usn := []byte{0x07, 0x00}
	copy(b[0x30:], usn)
	for i := 1; i < usaCount; i++ {
		end := i*stride - 2
		copy(b[0x30+2*i:], b[end:end+2])
		copy(b[end:], usn)
	}
	return b
}

// Image is an NTFS volume under construction.
type Image struct {
	B      []byte
	bitmap []byte
}

// New creates a volume with boot sectors and metadata clusters allocated.
func New() *Image {
	im := &Image{B: make([]byte, Clusters*CS+512), bitmap: make([]byte, Clusters/8)}
	bs := im.B
	bs[0], bs[1], bs[2] = 0xEB, 0x52, 0x90
	copy(bs[3:], "NTFS    ")
	binary.LittleEndian.PutUint16(bs[11:], 512)
	bs[13] = CS / 512
	binary.LittleEndian.PutUint64(bs[40:], Clusters*CS/512)
	binary.LittleEndian.PutUint64(bs[48:], MFTLCN)
	binary.LittleEndian.PutUint64(bs[56:], MirrLCN)
	bs[64] = 0xF6 // 2^10 = 1024-byte records
	bs[68] = 1
	bs[510], bs[511] = 0x55, 0xAA
	copy(im.B[Clusters*CS:], bs[:512]) // backup boot sector
	for c := int64(0); c <= BmpLCN; c++ {
		im.Alloc(c)
	}
	return im
}

// Alloc marks a cluster in use in $Bitmap.
func (im *Image) Alloc(lcn int64) { im.bitmap[lcn/8] |= 1 << (lcn % 8) }

// Put writes a record into the MFT.
func (im *Image) Put(s Rec) { copy(im.B[MFTLCN*CS+int(s.Num)*RS:], Record(s)) }

// Write stores data starting at cluster lcn.
func (im *Image) Write(lcn int64, data []byte) { copy(im.B[lcn*CS:], data) }

// Finish writes the system records, $MFTMirr and $Bitmap and returns the image.
func (im *Image) Finish() []byte {
	im.Put(Rec{Num: 0, Seq: 1, Flags: FlagInUse, Attrs: [][]byte{
		FileName(Root, "$MFT", NSWin32DOS), Data(Records*RS, Run{MFTLCN, Records * RS / CS})}})
	im.Put(Rec{Num: 5, Seq: 5, Flags: FlagInUse | FlagDirectory, Attrs: [][]byte{FileName(Root, ".", NSWin32DOS)}})
	im.Put(Rec{Num: 6, Seq: 6, Flags: FlagInUse, Attrs: [][]byte{
		FileName(Root, "$Bitmap", NSWin32DOS), Data(int64(len(im.bitmap)), Run{BmpLCN, 1})}})
	copy(im.B[MirrLCN*CS:], im.B[MFTLCN*CS:MFTLCN*CS+4*RS])
	im.Write(BmpLCN, im.bitmap)
	return im.B
}
