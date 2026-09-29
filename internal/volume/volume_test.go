package volume

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
	"unicode/utf16"
)

func putMBREntry(sec []byte, i int, boot bool, typ byte, lba, count uint32) {
	e := sec[446+i*16:]
	if boot {
		e[0] = 0x80
	}
	e[4] = typ
	binary.LittleEndian.PutUint32(e[8:], lba)
	binary.LittleEndian.PutUint32(e[12:], count)
	sec[510], sec[511] = 0x55, 0xAA
}

func TestMBRWithLogicalPartitions(t *testing.T) {
	const ss = 512
	disk := make([]byte, 4096*ss)
	putMBREntry(disk, 0, true, 0x07, 2048, 1000)
	putMBREntry(disk, 1, false, 0x0F, 3072, 1000) // extended
	// EBR 1 at 3072: logical at +63, link to next EBR at ext+500.
	ebr1 := disk[3072*ss:]
	putMBREntry(ebr1, 0, false, 0x83, 63, 400)
	putMBREntry(ebr1, 1, false, 0x05, 500, 400)
	ebr2 := disk[(3072+500)*ss:]
	putMBREntry(ebr2, 0, false, 0x0B, 63, 300)

	tab, err := Read(bytes.NewReader(disk), int64(len(disk)), ss)
	if err != nil {
		t.Fatal(err)
	}
	if tab.Scheme != SchemeMBR || len(tab.Partitions) != 3 {
		t.Fatalf("got %+v", tab)
	}
	want := []struct {
		start int64
		name  string
	}{
		{2048 * ss, "NTFS/exFAT/HPFS"},
		{(3072 + 63) * ss, "Linux"},
		{(3072 + 500 + 63) * ss, "FAT32"},
	}
	for i, w := range want {
		p := tab.Partitions[i]
		if p.Start != w.start || p.TypeName != w.name {
			t.Errorf("partition %d = start %d %q, want %d %q", i, p.Start, p.TypeName, w.start, w.name)
		}
	}
}

func TestEBRLoopIsBounded(t *testing.T) {
	const ss = 512
	disk := make([]byte, 4096*ss)
	putMBREntry(disk, 0, false, 0x05, 100, 1000)
	ebr := disk[100*ss:]
	putMBREntry(ebr, 0, false, 0x83, 1, 10)
	putMBREntry(ebr, 1, false, 0x05, 0x0, 10) // lba 0 terminates
	putMBREntry(ebr, 1, false, 0x05, 200, 10)
	loop := disk[300*ss:]
	putMBREntry(loop, 0, false, 0x83, 1, 10)
	putMBREntry(loop, 1, false, 0x05, 200, 10) // points to itself

	tab, err := Read(bytes.NewReader(disk), int64(len(disk)), ss)
	if err != nil {
		t.Fatal(err)
	}
	if len(tab.Partitions) != 2 || len(tab.Warnings) == 0 {
		t.Fatalf("expected 2 partitions and a loop warning, got %+v", tab)
	}
}

// buildGPT writes a protective MBR, primary and backup GPT to disk.
func buildGPT(disk []byte, ss int, parts [][2]uint64, names []string) {
	bss := uint64(ss)
	lastLBA := uint64(len(disk))/bss - 1
	putMBREntry(disk, 0, false, 0xEE, 1, uint32(lastLBA))

	entries := make([]byte, 128*128)
	basic := []byte{0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7}
	for i, p := range parts {
		e := entries[i*128:]
		copy(e[0:16], basic)
		e[16] = byte(i + 1)
		binary.LittleEndian.PutUint64(e[32:], p[0])
		binary.LittleEndian.PutUint64(e[40:], p[1])
		for j, c := range utf16.Encode([]rune(names[i])) {
			binary.LittleEndian.PutUint16(e[56+2*j:], c)
		}
	}
	entriesCRC := crc32.ChecksumIEEE(entries)
	entrySectors := uint64(len(entries)) / bss

	write := func(at, backup, entriesLBA uint64) {
		h := make([]byte, 92)
		copy(h, gptSignature)
		binary.LittleEndian.PutUint32(h[8:], 0x00010000)
		binary.LittleEndian.PutUint32(h[12:], 92)
		binary.LittleEndian.PutUint64(h[24:], at)
		binary.LittleEndian.PutUint64(h[32:], backup)
		binary.LittleEndian.PutUint64(h[40:], 2+entrySectors)
		binary.LittleEndian.PutUint64(h[48:], lastLBA-1-entrySectors)
		binary.LittleEndian.PutUint64(h[72:], entriesLBA)
		binary.LittleEndian.PutUint32(h[80:], 128)
		binary.LittleEndian.PutUint32(h[84:], 128)
		binary.LittleEndian.PutUint32(h[88:], entriesCRC)
		binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h))
		copy(disk[at*bss:], h)
		copy(disk[entriesLBA*bss:], entries)
	}
	write(1, lastLBA, 2)
	write(lastLBA, 1, lastLBA-entrySectors)
}

func TestGPTPrimaryAndBackup(t *testing.T) {
	for _, ss := range []int{512, 4096} {
		disk := make([]byte, 2048*ss)
		buildGPT(disk, ss, [][2]uint64{{40, 99}, {100, 1000}}, []string{"EFI", "Données"})

		tab, err := Read(bytes.NewReader(disk), int64(len(disk)), 512)
		if err != nil {
			t.Fatalf("ss=%d: %v", ss, err)
		}
		if tab.Scheme != SchemeGPT || tab.SectorSize != ss || len(tab.Partitions) != 2 {
			t.Fatalf("ss=%d: got %+v", ss, tab)
		}
		p := tab.Partitions[1]
		if p.Start != 100*int64(ss) || p.Size != 901*int64(ss) || p.Name != "Données" || p.TypeName != "Microsoft basic data" {
			t.Fatalf("ss=%d: partition = %+v", ss, p)
		}

		// Destroy the primary header: the backup must be used.
		disk[ss+20] ^= 0xFF
		tab, err = Read(bytes.NewReader(disk), int64(len(disk)), ss)
		if err != nil {
			t.Fatalf("ss=%d backup: %v", ss, err)
		}
		if len(tab.Partitions) != 2 || len(tab.Warnings) == 0 {
			t.Fatalf("ss=%d: backup GPT not used: %+v", ss, tab)
		}
	}
}

func TestWipedMBRWithIntactGPT(t *testing.T) {
	disk := make([]byte, 2048*512)
	buildGPT(disk, 512, [][2]uint64{{64, 1000}}, []string{"data"})
	for i := 0; i < 512; i++ {
		disk[i] = 0
	}
	tab, err := Read(bytes.NewReader(disk), int64(len(disk)), 512)
	if err != nil || tab.Scheme != SchemeGPT || len(tab.Partitions) != 1 {
		t.Fatalf("got %+v, %v", tab, err)
	}
}

func FuzzRead(f *testing.F) {
	disk := make([]byte, 64*512)
	buildGPT(disk, 512, [][2]uint64{{34, 40}}, []string{"x"})
	f.Add(disk)
	mbr := make([]byte, 16*512)
	putMBREntry(mbr, 0, false, 0x05, 2, 10)
	f.Add(mbr)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < 512 {
			return
		}
		_, _ = Read(bytes.NewReader(b), int64(len(b)), 512)
	})
}
