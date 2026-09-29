// Package fsdetect identifies file systems and finds lost partitions by
// scanning raw media for boot sectors and superblocks, including their
// backup copies, and reasoning back to where each volume must start.
package fsdetect

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/shanurwan/barerelic/internal/fs/fat"
	"github.com/shanurwan/barerelic/internal/fs/ntfs"
)

// FS describes an identified file system.
type FS struct {
	Type   string `json:"type"`
	Label  string `json:"label,omitempty"`
	Size   int64  `json:"size,omitempty"` // declared by the file system
	Detail string `json:"detail,omitempty"`
	// Recoverable is true when barerelic can walk this file system's metadata.
	Recoverable bool `json:"recoverable"`
}

const probeLen = 68 * 1024

// Identify inspects the volume starting at off.
func Identify(r io.ReaderAt, off int64) (FS, bool) {
	b := make([]byte, probeLen)
	n, _ := r.ReadAt(b, off)
	if n < 512 {
		return FS{}, false
	}
	b = b[:n]
	at := func(o int, sig string) bool { return len(b) >= o+len(sig) && string(b[o:o+len(sig)]) == sig }

	if bs, err := ntfs.ParseBootSector(b[:512]); err == nil {
		return FS{Type: "ntfs", Size: bs.VolumeSize(), Recoverable: true,
			Detail: fmt.Sprintf("cluster %d, MFT record %d, serial %016X", bs.ClusterSize(), bs.RecordSize, bs.Serial)}, true
	}
	if at(3, "EXFAT   ") {
		fs := FS{Type: "exfat"}
		if len(b) >= 110 && b[108] >= 9 && b[108] <= 12 {
			fs.Size = int64(binary.LittleEndian.Uint64(b[72:])) << b[108]
		}
		return fs, true
	}
	if at(3, "-FVE-FS-") {
		return FS{Type: "bitlocker", Detail: "BitLocker-encrypted volume; recovery requires the recovery key"}, true
	}
	if at(3, "ReFS") {
		return FS{Type: "refs"}, true
	}
	if bs, err := fat.ParseBootSector(b[:512]); err == nil {
		return FS{Type: strings.ToLower(bs.Type.String()), Label: bs.Label, Size: bs.VolumeSize(), Recoverable: true,
			Detail: fmt.Sprintf("cluster %d, %d clusters", bs.ClusterSize(), bs.ClusterCount)}, true
	}
	if at(0, "LUKS\xba\xbe") {
		return FS{Type: "luks", Detail: "LUKS-encrypted container"}, true
	}
	if at(512, "LABELONE") {
		return FS{Type: "lvm2", Detail: "LVM2 physical volume"}, true
	}
	if sb, ok := parseExtSuper(b, 1024); ok && sb.group == 0 {
		return FS{Type: sb.kind(), Label: sb.label, Size: sb.size(), Detail: fmt.Sprintf("block %d", sb.blockSize)}, true
	}
	if at(0, "XFSB") {
		return FS{Type: "xfs", Size: int64(binary.BigEndian.Uint64(b[8:])) * int64(binary.BigEndian.Uint32(b[4:]))}, true
	}
	if at(65536+64, "_BHRfS_M") {
		return FS{Type: "btrfs"}, true
	}
	if at(32, "NXSB") {
		return FS{Type: "apfs"}, true
	}
	if at(1024, "H+") || at(1024, "HX") {
		return FS{Type: "hfsplus"}, true
	}
	if len(b) >= 1028 && binary.LittleEndian.Uint32(b[1024:]) == 0xF2F52010 {
		return FS{Type: "f2fs"}, true
	}
	if at(32769, "CD001") {
		return FS{Type: "iso9660"}, true
	}
	if at(4096-10, "SWAPSPACE2") {
		return FS{Type: "linux-swap"}, true
	}
	return FS{}, false
}

type extSuper struct {
	blocksCount      uint64
	blockSize        int64
	blocksPerGroup   uint32
	firstDataBlock   uint32
	group            uint16
	label            string
	compat, incompat uint32
}

func (s extSuper) size() int64 { return int64(s.blocksCount) * s.blockSize }

func (s extSuper) kind() string {
	switch {
	case s.incompat&0x0040 != 0 || s.incompat&0x0080 != 0 || s.incompat&0x0200 != 0: // extents, 64bit, flex_bg
		return "ext4"
	case s.compat&0x0004 != 0: // has_journal
		return "ext3"
	}
	return "ext2"
}

// parseExtSuper validates an ext2/3/4 superblock at b[o:].
func parseExtSuper(b []byte, o int) (extSuper, bool) {
	if len(b) < o+0x160 || binary.LittleEndian.Uint16(b[o+56:]) != 0xEF53 {
		return extSuper{}, false
	}
	le32 := func(x int) uint32 { return binary.LittleEndian.Uint32(b[o+x:]) }
	logBS := le32(24)
	if logBS > 6 {
		return extSuper{}, false
	}
	s := extSuper{
		blocksCount:    uint64(le32(4)),
		blockSize:      1024 << logBS,
		blocksPerGroup: le32(32),
		firstDataBlock: le32(20),
		group:          binary.LittleEndian.Uint16(b[o+90:]),
		compat:         le32(92),
		incompat:       le32(96),
		label:          strings.TrimRight(string(b[o+120:o+136]), "\x00 "),
	}
	if s.incompat&0x80 != 0 {
		s.blocksCount |= uint64(le32(0x150)) << 32
	}
	inodes, ipg := le32(0), le32(40)
	rev := le32(76)
	wantFirst := uint32(0)
	if s.blockSize == 1024 {
		wantFirst = 1
	}
	if s.blocksCount == 0 || inodes == 0 || ipg == 0 || s.blocksPerGroup == 0 || s.blocksPerGroup > 8*uint32(s.blockSize) ||
		rev > 1 || s.firstDataBlock != wantFirst || uint64(s.blocksPerGroup)*uint64(s.group) >= s.blocksCount {
		return extSuper{}, false
	}
	return s, true
}

// Candidate is a volume start inferred from on-disk structures.
type Candidate struct {
	Start      int64  `json:"start"`
	FS         FS     `json:"fs"`
	Evidence   string `json:"evidence"`
	Confidence string `json:"confidence"`
}

// ScanOptions tune a lost-partition scan.
type ScanOptions struct {
	Start, End int64 // byte range to scan; End 0 = whole source
	Progress   func(pos int64)
}

// ScanLost scans every 512-byte-aligned position for boot sectors and
// superblocks (primary and backup) and returns plausible volume starts.
func ScanLost(ctx context.Context, r io.ReaderAt, size int64, opt ScanOptions) ([]Candidate, error) {
	end := opt.End
	if end <= 0 || end > size {
		end = size
	}
	const chunk = 4 << 20
	const overlap = 2048
	buf := make([]byte, chunk+overlap)
	found := map[string]Candidate{}
	add := func(c Candidate) {
		if c.Start < 0 || c.Start >= size {
			return
		}
		key := fmt.Sprintf("%d/%s", c.Start, c.FS.Type)
		if old, ok := found[key]; ok && rank(old.Confidence) >= rank(c.Confidence) {
			return
		}
		found[key] = c
	}
	for base := opt.Start - opt.Start%512; base < end; base += chunk {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, _ := r.ReadAt(buf[:min(int64(len(buf)), size-base)], base)
		for i := 0; i+512 <= n && i < chunk; i += 512 {
			pos := base + int64(i)
			if pos >= end {
				break
			}
			sec := buf[i : i+512]
			switch {
			case string(sec[3:11]) == "NTFS    ":
				scanNTFS(r, pos, sec, add)
			case string(sec[3:11]) == "EXFAT   ":
				scanExFAT(r, pos, sec, add)
			case sec[510] == 0x55 && sec[511] == 0xAA:
				scanFAT(r, pos, sec, add)
			}
			if i+1024 <= n {
				if sb, ok := parseExtSuper(buf[i:n], 0); ok {
					var start int64
					if sb.group == 0 {
						start = pos - 1024
					} else {
						start = pos - (int64(sb.firstDataBlock)+int64(sb.group)*int64(sb.blocksPerGroup))*sb.blockSize
					}
					ev := "primary superblock"
					if sb.group != 0 {
						ev = fmt.Sprintf("backup superblock (group %d) at 0x%X", sb.group, pos)
					}
					add(Candidate{Start: start, FS: FS{Type: sb.kind(), Label: sb.label, Size: sb.size()}, Evidence: ev, Confidence: "medium"})
				}
			}
		}
		if opt.Progress != nil {
			opt.Progress(min(base+chunk, end))
		}
	}
	out := make([]Candidate, 0, len(found))
	for _, c := range found {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		return out[i].FS.Type < out[j].FS.Type
	})
	return out, nil
}

func rank(c string) int {
	switch c {
	case "high":
		return 3
	case "medium":
		return 2
	}
	return 1
}

// scanNTFS evaluates both hypotheses for an NTFS boot sector: it is the
// primary (volume starts here) or the backup in the volume's last sector.
// The hypothesis under which $MFT record 0 is found wins.
func scanNTFS(r io.ReaderAt, pos int64, sec []byte, add func(Candidate)) {
	bs, err := ntfs.ParseBootSector(sec)
	if err != nil {
		return
	}
	fs := FS{Type: "ntfs", Size: bs.VolumeSize(), Recoverable: true}
	mftOK := func(start int64) bool {
		b := make([]byte, 4)
		_, err := r.ReadAt(b, start+int64(bs.MFTCluster)*bs.ClusterSize())
		return err == nil && string(b) == "FILE"
	}
	primary, backup := pos, pos-bs.VolumeSize()
	switch {
	case mftOK(primary):
		add(Candidate{Start: primary, FS: fs, Evidence: "boot sector; $MFT found at declared location", Confidence: "high"})
	case backup >= 0 && mftOK(backup):
		add(Candidate{Start: backup, FS: fs, Evidence: fmt.Sprintf("backup boot sector at 0x%X; $MFT found at declared location", pos), Confidence: "high"})
	default:
		add(Candidate{Start: primary, FS: fs, Evidence: "boot sector only; $MFT not found (damaged or not a volume start)", Confidence: "low"})
	}
}

// scanExFAT reports exFAT main boot sectors; a sector that is itself the
// backup (12 sectors after another exFAT boot sector) is ignored.
func scanExFAT(r io.ReaderAt, pos int64, sec []byte, add func(Candidate)) {
	shift := sec[108]
	if shift < 9 || shift > 12 {
		return
	}
	bps := int64(1) << shift
	if prev := pos - 12*bps; prev >= 0 {
		p := make([]byte, 11)
		if _, err := r.ReadAt(p, prev); err == nil && string(p[3:11]) == "EXFAT   " {
			return
		}
	}
	size := int64(binary.LittleEndian.Uint64(sec[72:])) << shift
	add(Candidate{Start: pos, FS: FS{Type: "exfat", Size: size}, Evidence: "main boot sector", Confidence: "medium"})
}

// scanFAT reports FAT boot sectors. A FAT32 boot sector may be the backup at
// sector 6; the hypothesis whose FAT region starts with the media byte wins.
func scanFAT(r io.ReaderAt, pos int64, sec []byte, add func(Candidate)) {
	bs, err := fat.ParseBootSector(sec)
	if err != nil {
		return
	}
	fs := FS{Type: strings.ToLower(bs.Type.String()), Label: bs.Label, Size: bs.VolumeSize(), Recoverable: true}
	fatOK := func(start int64) bool {
		b := make([]byte, 2)
		_, err := r.ReadAt(b, start+int64(bs.ReservedSectors)*int64(bs.BytesPerSector))
		return err == nil && b[0] == bs.Media && b[1] == 0xFF
	}
	if fatOK(pos) {
		add(Candidate{Start: pos, FS: fs, Evidence: "boot sector; FAT media byte matches", Confidence: "high"})
		return
	}
	if bs.Type == fat.FAT32 && bs.BackupBootSector > 0 {
		start := pos - int64(bs.BackupBootSector)*int64(bs.BytesPerSector)
		if start >= 0 && fatOK(start) {
			add(Candidate{Start: start, FS: fs, Evidence: fmt.Sprintf("backup boot sector at 0x%X; FAT media byte matches", pos), Confidence: "high"})
			return
		}
	}
	if bytes.Equal(sec[0:1], []byte{0xEB}) {
		add(Candidate{Start: pos, FS: fs, Evidence: "boot sector only; FAT region does not match", Confidence: "low"})
	}
}
