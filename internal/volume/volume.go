// Package volume parses partition tables (MBR with extended/logical
// partitions, and GPT with CRC validation and backup-header fallback).
//
// All parsing is defensive: evidence is untrusted, may be damaged, and may be
// crafted to trigger loops or huge allocations.
package volume

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"unicode/utf16"
)

// Scheme is a partitioning scheme.
type Scheme string

const (
	SchemeNone Scheme = "none"
	SchemeMBR  Scheme = "mbr"
	SchemeGPT  Scheme = "gpt"
)

// Partition is one entry of a partition table. Offsets are in bytes.
type Partition struct {
	Index    int    `json:"index"`
	Scheme   Scheme `json:"scheme"`
	Start    int64  `json:"start"`
	Size     int64  `json:"size"`
	Type     string `json:"type"`
	TypeName string `json:"type_name,omitempty"`
	Name     string `json:"name,omitempty"`
	GUID     string `json:"guid,omitempty"`
	Bootable bool   `json:"bootable,omitempty"`
	Logical  bool   `json:"logical,omitempty"`
}

// End returns the exclusive end offset.
func (p Partition) End() int64 { return p.Start + p.Size }

// Table is a parsed partition table.
type Table struct {
	Scheme     Scheme      `json:"scheme"`
	SectorSize int         `json:"sector_size"`
	DiskGUID   string      `json:"disk_guid,omitempty"`
	Partitions []Partition `json:"partitions"`
	Warnings   []string    `json:"warnings,omitempty"`
}

const (
	maxLogical   = 128
	maxGPTParts  = 1024
	gptSignature = "EFI PART"
)

// ErrNoTable is returned when no partition table is recognised.
var ErrNoTable = errors.New("no partition table found")

// Read parses the partition table of a disk of the given size. sectorSize
// is a hint; for GPT both 512 and 4096 are tried.
func Read(r io.ReaderAt, size int64, sectorSize int) (*Table, error) {
	if sectorSize <= 0 {
		sectorSize = 512
	}
	mbr := make([]byte, 512)
	if _, err := r.ReadAt(mbr, 0); err != nil {
		return nil, fmt.Errorf("read sector 0: %w", err)
	}
	hasMBR := mbr[510] == 0x55 && mbr[511] == 0xAA

	protective := false
	if hasMBR {
		for i := 0; i < 4; i++ {
			if mbr[446+i*16+4] == 0xEE {
				protective = true
			}
		}
	}

	// Try GPT when the MBR is protective, or when no valid MBR exists (a
	// wiped MBR with an intact GPT is a common damage pattern).
	if protective || !hasMBR {
		sizes := []int{sectorSize}
		for _, s := range []int{512, 4096} {
			if s != sectorSize {
				sizes = append(sizes, s)
			}
		}
		var gptErr error
		for _, ss := range sizes {
			t, err := readGPT(r, size, ss)
			if err == nil {
				if !hasMBR {
					t.Warnings = append(t.Warnings, "protective MBR missing; GPT found directly")
				}
				return t, nil
			}
			gptErr = errors.Join(gptErr, fmt.Errorf("sector size %d: %w", ss, err))
		}
		if protective {
			return nil, fmt.Errorf("protective MBR present but GPT unreadable: %w", gptErr)
		}
	}
	if !hasMBR {
		return nil, ErrNoTable
	}
	return readMBR(r, size, mbr, sectorSize)
}

type mbrEntry struct {
	boot  bool
	typ   byte
	lba   uint32
	count uint32
}

func parseMBREntries(sec []byte) [4]mbrEntry {
	var out [4]mbrEntry
	for i := range out {
		e := sec[446+i*16 : 446+(i+1)*16]
		out[i] = mbrEntry{
			boot:  e[0] == 0x80,
			typ:   e[4],
			lba:   binary.LittleEndian.Uint32(e[8:]),
			count: binary.LittleEndian.Uint32(e[12:]),
		}
	}
	return out
}

func isExtended(t byte) bool { return t == 0x05 || t == 0x0F || t == 0x85 }

func readMBR(r io.ReaderAt, size int64, sec []byte, ss int) (*Table, error) {
	t := &Table{Scheme: SchemeMBR, SectorSize: ss}
	bss := int64(ss)
	idx := 0
	var extStart int64 = -1
	for _, e := range parseMBREntries(sec) {
		if e.typ == 0 || e.count == 0 {
			continue
		}
		// Status bytes other than 0x00/0x80 usually mean this is not an MBR.
		if isExtended(e.typ) {
			extStart = int64(e.lba)
			continue
		}
		idx++
		p := Partition{Index: idx, Scheme: SchemeMBR, Start: int64(e.lba) * bss, Size: int64(e.count) * bss,
			Type: fmt.Sprintf("0x%02X", e.typ), TypeName: mbrTypeName(e.typ), Bootable: e.boot}
		t.addChecked(p, size)
	}
	for i := 0; i < 4; i++ {
		if s := sec[446+i*16]; s != 0x00 && s != 0x80 {
			t.Warnings = append(t.Warnings, fmt.Sprintf("MBR entry %d has non-standard status byte 0x%02X", i+1, s))
		}
	}
	if extStart >= 0 {
		t.readEBRChain(r, size, extStart, &idx)
	}
	return t, nil
}

// readEBRChain walks logical partitions. Each EBR's first entry is relative to
// the EBR itself; its second entry (the link) is relative to the extended
// partition start. Loops and runaway chains are bounded.
func (t *Table) readEBRChain(r io.ReaderAt, size int64, extStart int64, idx *int) {
	bss := int64(t.SectorSize)
	seen := map[int64]bool{}
	ebr := extStart
	sec := make([]byte, 512)
	for n := 0; n < maxLogical; n++ {
		if seen[ebr] {
			t.Warnings = append(t.Warnings, fmt.Sprintf("EBR chain loops at LBA %d", ebr))
			return
		}
		seen[ebr] = true
		if _, err := r.ReadAt(sec, ebr*bss); err != nil {
			t.Warnings = append(t.Warnings, fmt.Sprintf("EBR at LBA %d unreadable: %v", ebr, err))
			return
		}
		if sec[510] != 0x55 || sec[511] != 0xAA {
			t.Warnings = append(t.Warnings, fmt.Sprintf("EBR at LBA %d has no boot signature", ebr))
			return
		}
		ents := parseMBREntries(sec)
		if e := ents[0]; e.typ != 0 && e.count != 0 {
			*idx++
			p := Partition{Index: *idx, Scheme: SchemeMBR, Start: (ebr + int64(e.lba)) * bss, Size: int64(e.count) * bss,
				Type: fmt.Sprintf("0x%02X", e.typ), TypeName: mbrTypeName(e.typ), Bootable: e.boot, Logical: true}
			t.addChecked(p, size)
		}
		link := ents[1]
		if !isExtended(link.typ) || link.lba == 0 {
			return
		}
		ebr = extStart + int64(link.lba)
	}
	t.Warnings = append(t.Warnings, fmt.Sprintf("EBR chain exceeds %d entries; truncated", maxLogical))
}

func (t *Table) addChecked(p Partition, size int64) {
	if p.End() > size {
		t.Warnings = append(t.Warnings, fmt.Sprintf("partition %d extends %d bytes past the end of the source (truncated image or wrong table?)", p.Index, p.End()-size))
	}
	t.Partitions = append(t.Partitions, p)
}

type gptHeader struct {
	current, backup, firstUsable, lastUsable uint64
	diskGUID                                 [16]byte
	entriesLBA                               uint64
	numEntries, entrySize, entriesCRC        uint32
}

func parseGPTHeader(b []byte) (*gptHeader, error) {
	if string(b[:8]) != gptSignature {
		return nil, errors.New("no GPT signature")
	}
	hsize := binary.LittleEndian.Uint32(b[12:])
	if hsize < 92 || int(hsize) > len(b) {
		return nil, fmt.Errorf("bad GPT header size %d", hsize)
	}
	want := binary.LittleEndian.Uint32(b[16:])
	tmp := append([]byte(nil), b[:hsize]...)
	binary.LittleEndian.PutUint32(tmp[16:], 0)
	if got := crc32.ChecksumIEEE(tmp); got != want {
		return nil, fmt.Errorf("GPT header CRC mismatch (0x%08X != 0x%08X)", got, want)
	}
	h := &gptHeader{
		current:     binary.LittleEndian.Uint64(b[24:]),
		backup:      binary.LittleEndian.Uint64(b[32:]),
		firstUsable: binary.LittleEndian.Uint64(b[40:]),
		lastUsable:  binary.LittleEndian.Uint64(b[48:]),
		entriesLBA:  binary.LittleEndian.Uint64(b[72:]),
		numEntries:  binary.LittleEndian.Uint32(b[80:]),
		entrySize:   binary.LittleEndian.Uint32(b[84:]),
		entriesCRC:  binary.LittleEndian.Uint32(b[88:]),
	}
	copy(h.diskGUID[:], b[56:72])
	if h.entrySize < 128 || h.entrySize%8 != 0 || h.entrySize > 4096 {
		return nil, fmt.Errorf("bad GPT entry size %d", h.entrySize)
	}
	if h.numEntries == 0 || h.numEntries > maxGPTParts {
		return nil, fmt.Errorf("implausible GPT entry count %d", h.numEntries)
	}
	return h, nil
}

func readGPT(r io.ReaderAt, size int64, ss int) (*Table, error) {
	bss := int64(ss)
	hdr := make([]byte, ss)
	lastLBA := size/bss - 1

	type candidate struct {
		lba   int64
		label string
	}
	var errs error
	for _, c := range []candidate{{1, "primary"}, {lastLBA, "backup"}} {
		if c.lba < 1 {
			continue
		}
		if _, err := r.ReadAt(hdr, c.lba*bss); err != nil {
			errs = errors.Join(errs, fmt.Errorf("%s header: %w", c.label, err))
			continue
		}
		h, err := parseGPTHeader(hdr)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("%s header: %w", c.label, err))
			continue
		}
		t, err := readGPTEntries(r, size, ss, h)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("%s entries: %w", c.label, err))
			continue
		}
		if c.label == "backup" {
			t.Warnings = append(t.Warnings, "primary GPT damaged; partitions read from backup GPT at end of disk")
		}
		return t, nil
	}
	return nil, errs
}

func readGPTEntries(r io.ReaderAt, size int64, ss int, h *gptHeader) (*Table, error) {
	bss := int64(ss)
	buf := make([]byte, int(h.numEntries)*int(h.entrySize))
	if _, err := r.ReadAt(buf, int64(h.entriesLBA)*bss); err != nil {
		return nil, err
	}
	if got := crc32.ChecksumIEEE(buf); got != h.entriesCRC {
		return nil, fmt.Errorf("partition array CRC mismatch (0x%08X != 0x%08X)", got, h.entriesCRC)
	}
	t := &Table{Scheme: SchemeGPT, SectorSize: ss, DiskGUID: formatGUID(h.diskGUID[:])}
	for i := 0; i < int(h.numEntries); i++ {
		e := buf[i*int(h.entrySize) : (i+1)*int(h.entrySize)]
		typ := formatGUID(e[0:16])
		if typ == zeroGUID {
			continue
		}
		first := binary.LittleEndian.Uint64(e[32:])
		last := binary.LittleEndian.Uint64(e[40:])
		if last < first {
			t.Warnings = append(t.Warnings, fmt.Sprintf("GPT entry %d has last LBA < first LBA; skipped", i+1))
			continue
		}
		p := Partition{
			Index: i + 1, Scheme: SchemeGPT,
			Start: int64(first) * bss, Size: int64(last-first+1) * bss,
			Type: typ, TypeName: gptTypeNames[typ],
			GUID: formatGUID(e[16:32]),
			Name: decodeUTF16Name(e[56:128]),
		}
		t.addChecked(p, size)
	}
	return t, nil
}

const zeroGUID = "00000000-0000-0000-0000-000000000000"

// formatGUID renders a mixed-endian on-disk GUID in canonical form.
func formatGUID(b []byte) string {
	return fmt.Sprintf("%08X-%04X-%04X-%X-%X",
		binary.LittleEndian.Uint32(b[0:]), binary.LittleEndian.Uint16(b[4:]),
		binary.LittleEndian.Uint16(b[6:]), b[8:10], b[10:16])
}

func decodeUTF16Name(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return strings.TrimSpace(string(utf16.Decode(u)))
}

var gptTypeNames = map[string]string{
	"C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System",
	"21686148-6449-6E6F-744E-656564454649": "BIOS boot",
	"E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft reserved",
	"EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft basic data",
	"DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows recovery",
	"5808C8AA-7E8F-42E0-85D2-E1E90434CFB3": "Windows LDM metadata",
	"AF9B60A0-1431-4F62-BC68-3311714A69AD": "Windows LDM data",
	"E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D": "Windows Storage Spaces",
	"0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux filesystem",
	"4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709": "Linux root (x86-64)",
	"B921B045-1DF0-41C3-AF44-4C6F280D3FAE": "Linux root (ARM64)",
	"933AC7E1-2EB4-4F13-B844-0E14E2AEF915": "Linux home",
	"0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux swap",
	"E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux LVM",
	"A19D880F-05FC-4D3B-A006-743F0F84911E": "Linux RAID",
	"CA7D7CCB-63ED-4C53-861C-1742536059CC": "Linux LUKS",
	"BC13C2FF-59E6-4262-A352-B275FD6F7172": "Linux extended boot",
	"48465300-0000-11AA-AA11-00306543ECAC": "Apple HFS+",
	"7C3457EF-0000-11AA-AA11-00306543ECAC": "Apple APFS",
	"426F6F74-0000-11AA-AA11-00306543ECAC": "Apple boot",
	"516E7CB4-6ECF-11D6-8FF8-00022D09712B": "FreeBSD data",
	"516E7CBA-6ECF-11D6-8FF8-00022D09712B": "FreeBSD ZFS",
	"6A898CC3-1DD2-11B2-99A6-080020736631": "ZFS (Solaris/illumos /usr)",
}

func mbrTypeName(t byte) string {
	switch t {
	case 0x01:
		return "FAT12"
	case 0x04, 0x06, 0x0E:
		return "FAT16"
	case 0x07:
		return "NTFS/exFAT/HPFS"
	case 0x0B, 0x0C:
		return "FAT32"
	case 0x11, 0x14, 0x16, 0x1B, 0x1C, 0x1E:
		return "hidden FAT"
	case 0x17:
		return "hidden NTFS/exFAT"
	case 0x27:
		return "Windows recovery"
	case 0x42:
		return "Windows dynamic disk"
	case 0x82:
		return "Linux swap"
	case 0x83:
		return "Linux"
	case 0x8E:
		return "Linux LVM"
	case 0xA5:
		return "FreeBSD"
	case 0xA6:
		return "OpenBSD"
	case 0xA8:
		return "Apple UFS"
	case 0xA9:
		return "NetBSD"
	case 0xAF:
		return "Apple HFS/HFS+"
	case 0xEE:
		return "GPT protective"
	case 0xEF:
		return "EFI System"
	case 0xFD:
		return "Linux RAID"
	}
	return ""
}
