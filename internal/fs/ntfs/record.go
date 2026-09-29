// Package ntfs reads NTFS volumes through the Master File Table and recovers
// deleted files.
//
// Deleting a file on NTFS clears the in-use flag of its MFT record and frees
// its clusters in $Bitmap, but the record's attributes, including $FILE_NAME
// and the $DATA runlist (or the data itself when resident), normally survive
// until the record is reused. Recovery reads those records and grades
// confidence by whether the file's clusters have since been reallocated.
package ntfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// Attribute type codes.
const (
	AttrStandardInformation = 0x10
	AttrAttributeList       = 0x20
	AttrFileName            = 0x30
	AttrData                = 0x80
	AttrEnd                 = 0xFFFFFFFF
)

// Record flags.
const (
	FlagInUse     = 0x0001
	FlagDirectory = 0x0002
)

// Attribute flags.
const (
	AttrFlagCompressed = 0x00FF
	AttrFlagEncrypted  = 0x4000
	AttrFlagSparse     = 0x8000
)

// fixupStride is the NTFS update-sequence stride, independent of sector size.
const fixupStride = 512

// Run is one mapping of virtual clusters to logical clusters. LCN < 0 is sparse.
type Run struct {
	VCN    int64
	LCN    int64
	Length int64
}

// Attr is a decoded attribute.
type Attr struct {
	Type        uint32
	Name        string
	NonResident bool
	Flags       uint16
	ID          uint16

	Value       []byte // resident value
	ValueOffset int    // offset of the resident value inside the record

	StartVCN, LastVCN             int64
	AllocSize, DataSize, InitSize int64
	CompressionUnit               uint16
	Runs                          []Run
}

// Record is a decoded MFT record.
type Record struct {
	Number    uint64
	HasNumber bool // record number stored in header (NTFS 3.1+)
	Sequence  uint16
	LinkCount uint16
	Flags     uint16
	BaseRef   uint64
	Attrs     []Attr
}

// InUse reports whether the record is allocated.
func (r *Record) InUse() bool { return r.Flags&FlagInUse != 0 }

// IsDir reports whether the record is a directory.
func (r *Record) IsDir() bool { return r.Flags&FlagDirectory != 0 }

// Ref splits an MFT reference into record number and sequence number.
func Ref(ref uint64) (num uint64, seq uint16) { return ref & 0x0000FFFFFFFFFFFF, uint16(ref >> 48) }

// ErrNotRecord means the buffer does not start with a FILE record signature.
var ErrNotRecord = errors.New("ntfs: not a FILE record")

// ApplyFixups validates and reverses the update sequence array in place. A
// mismatch means a torn write or a record that is not really a record.
func ApplyFixups(b []byte) error {
	if len(b) < 48 || string(b[:4]) != "FILE" {
		return ErrNotRecord
	}
	usaOff := int(binary.LittleEndian.Uint16(b[4:]))
	usaCount := int(binary.LittleEndian.Uint16(b[6:]))
	if usaCount < 2 || usaOff+2*usaCount > len(b) || (usaCount-1)*fixupStride > len(b) {
		return fmt.Errorf("ntfs: bad update sequence array (offset %d, count %d)", usaOff, usaCount)
	}
	usn := b[usaOff : usaOff+2]
	for i := 1; i < usaCount; i++ {
		end := i*fixupStride - 2
		if b[end] != usn[0] || b[end+1] != usn[1] {
			return fmt.Errorf("ntfs: fixup mismatch in stride %d (torn or corrupted record)", i)
		}
		copy(b[end:end+2], b[usaOff+2*i:usaOff+2*i+2])
	}
	return nil
}

// ParseRecord applies fixups to a copy of b and decodes the record.
func ParseRecord(b []byte) (*Record, error) {
	buf := append([]byte(nil), b...)
	if err := ApplyFixups(buf); err != nil {
		return nil, err
	}
	r := &Record{
		Sequence:  binary.LittleEndian.Uint16(buf[0x10:]),
		LinkCount: binary.LittleEndian.Uint16(buf[0x12:]),
		Flags:     binary.LittleEndian.Uint16(buf[0x16:]),
		BaseRef:   binary.LittleEndian.Uint64(buf[0x20:]),
	}
	attrOff := int(binary.LittleEndian.Uint16(buf[0x14:]))
	used := int(binary.LittleEndian.Uint32(buf[0x18:]))
	if used > len(buf) || used < attrOff {
		used = len(buf) // deleted records sometimes carry stale values; stay bounded
	}
	if attrOff >= 0x30 {
		r.Number = uint64(binary.LittleEndian.Uint32(buf[0x2C:]))
		r.HasNumber = true
	}
	for pos, n := attrOff, 0; pos+16 <= used && n < 256; n++ {
		typ := binary.LittleEndian.Uint32(buf[pos:])
		if typ == AttrEnd {
			break
		}
		length := int(binary.LittleEndian.Uint32(buf[pos+4:]))
		if length < 24 || length%8 != 0 || pos+length > used {
			return r, fmt.Errorf("ntfs: attribute 0x%X at %d has bad length %d", typ, pos, length)
		}
		a, err := parseAttr(buf[pos:pos+length], pos)
		if err != nil {
			return r, err
		}
		r.Attrs = append(r.Attrs, a)
		pos += length
	}
	return r, nil
}

func parseAttr(b []byte, recOff int) (Attr, error) {
	a := Attr{
		Type:        binary.LittleEndian.Uint32(b[0:]),
		NonResident: b[8] != 0,
		Flags:       binary.LittleEndian.Uint16(b[12:]),
		ID:          binary.LittleEndian.Uint16(b[14:]),
	}
	if nameLen, nameOff := int(b[9]), int(binary.LittleEndian.Uint16(b[10:])); nameLen > 0 {
		if nameOff+2*nameLen > len(b) {
			return a, errors.New("ntfs: attribute name out of bounds")
		}
		a.Name = decodeUTF16(b[nameOff : nameOff+2*nameLen])
	}
	if !a.NonResident {
		vlen := int(binary.LittleEndian.Uint32(b[16:]))
		voff := int(binary.LittleEndian.Uint16(b[20:]))
		if voff+vlen > len(b) || vlen < 0 {
			return a, errors.New("ntfs: resident value out of bounds")
		}
		a.Value = b[voff : voff+vlen]
		a.ValueOffset = recOff + voff
		a.DataSize, a.InitSize = int64(vlen), int64(vlen)
		return a, nil
	}
	if len(b) < 64 {
		return a, errors.New("ntfs: non-resident header truncated")
	}
	a.StartVCN = int64(binary.LittleEndian.Uint64(b[16:]))
	a.LastVCN = int64(binary.LittleEndian.Uint64(b[24:]))
	runOff := int(binary.LittleEndian.Uint16(b[32:]))
	a.CompressionUnit = binary.LittleEndian.Uint16(b[34:])
	a.AllocSize = int64(binary.LittleEndian.Uint64(b[40:]))
	a.DataSize = int64(binary.LittleEndian.Uint64(b[48:]))
	a.InitSize = int64(binary.LittleEndian.Uint64(b[56:]))
	if a.DataSize < 0 || a.InitSize < 0 || a.AllocSize < 0 {
		return a, errors.New("ntfs: negative attribute size")
	}
	if runOff > len(b) {
		return a, errors.New("ntfs: runlist offset out of bounds")
	}
	runs, err := DecodeRuns(b[runOff:], a.StartVCN)
	if err != nil {
		return a, err
	}
	a.Runs = runs
	return a, nil
}

// DecodeRuns decodes an NTFS mapping-pairs array starting at startVCN.
func DecodeRuns(b []byte, startVCN int64) ([]Run, error) {
	var runs []Run
	vcn, lcn := startVCN, int64(0)
	for i := 0; i < len(b); {
		h := b[i]
		if h == 0 {
			return runs, nil
		}
		lenSize, offSize := int(h&0x0F), int(h>>4)
		if lenSize == 0 || lenSize > 8 || offSize > 8 || i+1+lenSize+offSize > len(b) {
			return runs, fmt.Errorf("ntfs: malformed run header 0x%02X", h)
		}
		length := int64(readUint(b[i+1 : i+1+lenSize]))
		if length <= 0 {
			return runs, errors.New("ntfs: non-positive run length")
		}
		r := Run{VCN: vcn, Length: length, LCN: -1}
		if offSize > 0 {
			lcn += readInt(b[i+1+lenSize : i+1+lenSize+offSize])
			if lcn < 0 {
				return runs, errors.New("ntfs: run points before the volume start")
			}
			r.LCN = lcn
		}
		runs = append(runs, r)
		vcn += length
		i += 1 + lenSize + offSize
	}
	return runs, errors.New("ntfs: runlist not terminated")
}

func readUint(b []byte) uint64 {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

func readInt(b []byte) int64 {
	v := readUint(b)
	if n := uint(len(b)) * 8; n < 64 && v&(1<<(n-1)) != 0 {
		v |= ^uint64(0) << n
	}
	return int64(v)
}

func decodeUTF16(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// Namespaces of $FILE_NAME.
const (
	NSPOSIX    = 0
	NSWin32    = 1
	NSDOS      = 2
	NSWin32DOS = 3
)

// FileName is a decoded $FILE_NAME attribute.
type FileName struct {
	Parent    uint64
	Name      string
	Namespace byte
	Created   time.Time
	Modified  time.Time
	MFTChange time.Time
	Accessed  time.Time
	RealSize  int64
}

// ParseFileName decodes a $FILE_NAME value.
func ParseFileName(v []byte) (FileName, error) {
	if len(v) < 66 {
		return FileName{}, errors.New("ntfs: $FILE_NAME too short")
	}
	n := int(v[64])
	if 66+2*n > len(v) {
		return FileName{}, errors.New("ntfs: $FILE_NAME name out of bounds")
	}
	return FileName{
		Parent:    binary.LittleEndian.Uint64(v[0:]),
		Created:   filetime(v[8:]),
		Modified:  filetime(v[16:]),
		MFTChange: filetime(v[24:]),
		Accessed:  filetime(v[32:]),
		RealSize:  int64(binary.LittleEndian.Uint64(v[48:])),
		Namespace: v[65],
		Name:      decodeUTF16(v[66 : 66+2*n]),
	}, nil
}

// StdInfo holds $STANDARD_INFORMATION timestamps.
type StdInfo struct {
	Created, Modified, MFTChange, Accessed time.Time
}

func parseStdInfo(v []byte) (StdInfo, bool) {
	if len(v) < 32 {
		return StdInfo{}, false
	}
	return StdInfo{filetime(v[0:]), filetime(v[8:]), filetime(v[16:]), filetime(v[24:])}, true
}

// filetime converts a Windows FILETIME (100 ns since 1601-01-01 UTC).
func filetime(b []byte) time.Time {
	ft := binary.LittleEndian.Uint64(b)
	if ft == 0 {
		return time.Time{}
	}
	const epochDiff = 116444736000000000 // 1601→1970 in 100 ns units
	if ft < epochDiff || ft > epochDiff+(1<<62)/100 {
		return time.Time{}
	}
	d := int64(ft - epochDiff)
	return time.Unix(d/1e7, (d%1e7)*100).UTC()
}

// preferredName picks the most descriptive $FILE_NAME: Win32 or Win32+DOS
// over POSIX over the 8.3 DOS alias.
func preferredName(fns []FileName) (FileName, bool) {
	rank := func(ns byte) int {
		switch ns {
		case NSWin32, NSWin32DOS:
			return 3
		case NSPOSIX:
			return 2
		}
		return 1
	}
	best, ok := FileName{}, false
	for _, fn := range fns {
		if !ok || rank(fn.Namespace) > rank(best.Namespace) {
			best, ok = fn, true
		}
	}
	best.Name = strings.TrimRight(best.Name, "\x00")
	return best, ok
}
