package fsdetect

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
)

const mib = 1 << 20

func ntfsBoot(totalSectors uint64) []byte {
	b := make([]byte, 512)
	b[0], b[1], b[2] = 0xEB, 0x52, 0x90
	copy(b[3:], "NTFS    ")
	binary.LittleEndian.PutUint16(b[11:], 512)
	b[13] = 8
	binary.LittleEndian.PutUint64(b[40:], totalSectors)
	binary.LittleEndian.PutUint64(b[48:], 4)
	binary.LittleEndian.PutUint64(b[56:], 8)
	b[64] = 0xF6
	b[68] = 1
	b[510], b[511] = 0x55, 0xAA
	return b
}

func fat16Boot() []byte {
	b := make([]byte, 512)
	b[0], b[1], b[2] = 0xEB, 0x3C, 0x90
	copy(b[3:], "MSWIN4.1")
	binary.LittleEndian.PutUint16(b[11:], 512)
	b[13] = 1
	binary.LittleEndian.PutUint16(b[14:], 1)
	b[16] = 2
	binary.LittleEndian.PutUint16(b[17:], 512)
	binary.LittleEndian.PutUint16(b[19:], 4400)
	b[21] = 0xF8
	binary.LittleEndian.PutUint16(b[22:], 18)
	b[38] = 0x29
	copy(b[43:], "CAMERA     ")
	b[510], b[511] = 0x55, 0xAA
	return b
}

func extSuperblock(blocks, bpg uint32, group uint16, label string) []byte {
	s := make([]byte, 1024)
	binary.LittleEndian.PutUint32(s[0:], 128)    // inodes
	binary.LittleEndian.PutUint32(s[4:], blocks) // blocks
	binary.LittleEndian.PutUint32(s[20:], 1)     // first data block (1 KiB blocks)
	binary.LittleEndian.PutUint32(s[24:], 0)     // log block size -> 1024
	binary.LittleEndian.PutUint32(s[32:], bpg)
	binary.LittleEndian.PutUint32(s[40:], 64)
	binary.LittleEndian.PutUint16(s[56:], 0xEF53)
	binary.LittleEndian.PutUint32(s[76:], 1)
	binary.LittleEndian.PutUint16(s[90:], group)
	binary.LittleEndian.PutUint32(s[92:], 0x4)  // has_journal
	binary.LittleEndian.PutUint32(s[96:], 0x40) // extents
	copy(s[120:], label)
	return s
}

func TestIdentify(t *testing.T) {
	disk := make([]byte, 2*mib)
	copy(disk, ntfsBoot(2048))
	if fs, ok := Identify(bytes.NewReader(disk), 0); !ok || fs.Type != "ntfs" || !fs.Recoverable {
		t.Fatalf("ntfs: %+v", fs)
	}
	clear(disk)
	copy(disk, fat16Boot())
	if fs, ok := Identify(bytes.NewReader(disk), 0); !ok || fs.Type != "fat16" || fs.Label != "CAMERA" {
		t.Fatalf("fat16: %+v", fs)
	}
	clear(disk)
	copy(disk[1024:], extSuperblock(1024, 256, 0, "home"))
	if fs, ok := Identify(bytes.NewReader(disk), 0); !ok || fs.Type != "ext4" || fs.Label != "home" || fs.Size != mib {
		t.Fatalf("ext4: %+v", fs)
	}
	clear(disk)
	copy(disk[3:], "-FVE-FS-")
	if fs, _ := Identify(bytes.NewReader(disk), 0); fs.Type != "bitlocker" {
		t.Fatalf("bitlocker: %+v", fs)
	}
	clear(disk)
	if _, ok := Identify(bytes.NewReader(disk), 0); ok {
		t.Fatal("zeroed disk identified as a file system")
	}
}

func TestScanLostFindsVolumesFromBackups(t *testing.T) {
	disk := make([]byte, 8*mib)

	// NTFS at 1 MiB, 2 MiB long, primary boot sector destroyed: only the
	// backup at the end of the volume remains.
	const ntfsAt = 1 * mib
	nb := ntfsBoot(2 * mib / 512)
	copy(disk[ntfsAt+2*mib:], nb)
	copy(disk[ntfsAt+4*4096:], "FILE")

	// Intact FAT16 at 4 MiB.
	const fatAt = 4 * mib
	copy(disk[fatAt:], fat16Boot())
	disk[fatAt+512], disk[fatAt+513] = 0xF8, 0xFF

	// ext3/4 at 7 MiB whose primary superblock is gone; a group-1 backup survives.
	const extAt = 7 * mib
	copy(disk[extAt+(1+256)*1024:], extSuperblock(512, 256, 1, "data"))

	var progressed int64
	cands, err := ScanLost(context.Background(), bytes.NewReader(disk), int64(len(disk)), ScanOptions{Progress: func(p int64) { progressed = p }})
	if err != nil {
		t.Fatal(err)
	}
	want := map[int64]string{ntfsAt: "ntfs", fatAt: "fat16", extAt: "ext4"}
	for start, typ := range want {
		ok := false
		for _, c := range cands {
			if c.Start == start && c.FS.Type == typ {
				ok = true
				if typ != "ext4" && c.Confidence != "high" {
					t.Errorf("%s at %d: confidence %s", typ, start, c.Confidence)
				}
			}
		}
		if !ok {
			t.Errorf("%s volume at 0x%X not found; candidates: %+v", typ, start, cands)
		}
	}
	if progressed != int64(len(disk)) {
		t.Errorf("progress ended at %d", progressed)
	}
}
