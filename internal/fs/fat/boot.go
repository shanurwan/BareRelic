// Package fat reads FAT12/16/32 volumes and recovers deleted files.
//
// Deleting a file on FAT marks the first byte of its directory entry 0xE5 and
// zeroes its cluster chain in the FAT; the entry's size and start cluster
// usually survive. Recovery therefore reads ceil(size/cluster) clusters
// contiguously from the start cluster and grades confidence by whether those
// clusters have since been reallocated.
package fat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Type is the FAT variant, determined by cluster count as the spec requires
// (the "FAT16"/"FAT32" strings in the boot sector are informational only).
type Type int

const (
	FAT12 Type = 12
	FAT16 Type = 16
	FAT32 Type = 32
)

func (t Type) String() string { return fmt.Sprintf("FAT%d", int(t)) }

// BootSector holds the BIOS Parameter Block and derived geometry.
type BootSector struct {
	OEM               string
	BytesPerSector    uint32
	SectorsPerCluster uint32
	ReservedSectors   uint32
	NumFATs           uint32
	RootEntries       uint32
	TotalSectors      uint32
	Media             byte
	FATSize           uint32 // sectors per FAT
	RootCluster       uint32 // FAT32 only
	BackupBootSector  uint32 // FAT32 only
	VolumeID          uint32
	Label             string

	Type            Type
	RootDirSectors  uint32
	FirstDataSector uint32
	ClusterCount    uint32
}

// ClusterSize returns the cluster size in bytes.
func (b *BootSector) ClusterSize() int64 {
	return int64(b.BytesPerSector) * int64(b.SectorsPerCluster)
}

// VolumeSize returns the size declared by the BPB in bytes.
func (b *BootSector) VolumeSize() int64 {
	return int64(b.TotalSectors) * int64(b.BytesPerSector)
}

func isPow2(v uint32) bool { return v != 0 && v&(v-1) == 0 }

// ParseBootSector validates and decodes a FAT boot sector (at least 512 bytes).
func ParseBootSector(b []byte) (*BootSector, error) {
	if len(b) < 512 {
		return nil, errors.New("fat: boot sector shorter than 512 bytes")
	}
	if b[0] != 0xEB && b[0] != 0xE9 {
		return nil, errors.New("fat: no x86 jump instruction")
	}
	if b[510] != 0x55 || b[511] != 0xAA {
		return nil, errors.New("fat: missing 0x55AA signature")
	}
	le16 := func(o int) uint32 { return uint32(binary.LittleEndian.Uint16(b[o:])) }
	le32 := func(o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
	bs := &BootSector{
		OEM:               strings.TrimRight(string(b[3:11]), " \x00"),
		BytesPerSector:    le16(11),
		SectorsPerCluster: uint32(b[13]),
		ReservedSectors:   le16(14),
		NumFATs:           uint32(b[16]),
		RootEntries:       le16(17),
		TotalSectors:      le16(19),
		Media:             b[21],
		FATSize:           le16(22),
	}
	if bs.TotalSectors == 0 {
		bs.TotalSectors = le32(32)
	}
	switch {
	case !isPow2(bs.BytesPerSector) || bs.BytesPerSector < 512 || bs.BytesPerSector > 4096:
		return nil, fmt.Errorf("fat: bad bytes/sector %d", bs.BytesPerSector)
	case !isPow2(bs.SectorsPerCluster) || bs.SectorsPerCluster > 128:
		return nil, fmt.Errorf("fat: bad sectors/cluster %d", bs.SectorsPerCluster)
	case bs.BytesPerSector*bs.SectorsPerCluster > 256<<10:
		return nil, fmt.Errorf("fat: cluster size %d too large", bs.BytesPerSector*bs.SectorsPerCluster)
	case bs.ReservedSectors == 0:
		return nil, errors.New("fat: zero reserved sectors")
	case bs.NumFATs == 0 || bs.NumFATs > 4:
		return nil, fmt.Errorf("fat: bad FAT count %d", bs.NumFATs)
	case bs.Media != 0xF0 && bs.Media < 0xF8:
		return nil, fmt.Errorf("fat: bad media descriptor 0x%02X", bs.Media)
	case bs.TotalSectors == 0:
		return nil, errors.New("fat: zero total sectors")
	}
	fat32 := bs.FATSize == 0
	if fat32 {
		bs.FATSize = le32(36)
		bs.RootCluster = le32(44)
		bs.BackupBootSector = le16(50)
		if b[66] == 0x29 {
			bs.VolumeID = le32(67)
			bs.Label = strings.TrimRight(string(b[71:82]), " \x00")
		}
		if bs.RootEntries != 0 {
			return nil, errors.New("fat: FAT32 BPB with non-zero root entry count")
		}
	} else if b[38] == 0x29 {
		bs.VolumeID = le32(39)
		bs.Label = strings.TrimRight(string(b[43:54]), " \x00")
	}
	if bs.FATSize == 0 {
		return nil, errors.New("fat: zero FAT size")
	}

	bs.RootDirSectors = (bs.RootEntries*32 + bs.BytesPerSector - 1) / bs.BytesPerSector
	meta := uint64(bs.ReservedSectors) + uint64(bs.NumFATs)*uint64(bs.FATSize) + uint64(bs.RootDirSectors)
	if meta >= uint64(bs.TotalSectors) {
		return nil, errors.New("fat: metadata region exceeds volume")
	}
	bs.FirstDataSector = uint32(meta)
	bs.ClusterCount = (bs.TotalSectors - bs.FirstDataSector) / bs.SectorsPerCluster
	switch {
	case bs.ClusterCount < 4085:
		bs.Type = FAT12
	case bs.ClusterCount < 65525:
		bs.Type = FAT16
	default:
		bs.Type = FAT32
	}
	if (bs.Type == FAT32) != fat32 {
		return nil, fmt.Errorf("fat: BPB layout disagrees with cluster count %d", bs.ClusterCount)
	}
	// The FAT must be large enough to describe every cluster.
	entryBits := uint64(bs.Type)
	if need := (uint64(bs.ClusterCount+2)*entryBits + 7) / 8; need > uint64(bs.FATSize)*uint64(bs.BytesPerSector) {
		return nil, fmt.Errorf("fat: FAT too small for %d clusters", bs.ClusterCount)
	}
	if bs.Type == FAT32 && (bs.RootCluster < 2 || bs.RootCluster >= bs.ClusterCount+2) {
		return nil, fmt.Errorf("fat: root cluster %d out of range", bs.RootCluster)
	}
	return bs, nil
}
