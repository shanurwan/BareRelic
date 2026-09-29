package ntfs

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// BootSector holds NTFS volume geometry.
type BootSector struct {
	BytesPerSector    uint32
	SectorsPerCluster uint32
	TotalSectors      uint64
	MFTCluster        uint64
	MFTMirrCluster    uint64
	RecordSize        uint32
	IndexRecordSize   uint32
	Serial            uint64
}

// ClusterSize returns the cluster size in bytes.
func (b *BootSector) ClusterSize() int64 {
	return int64(b.BytesPerSector) * int64(b.SectorsPerCluster)
}

// VolumeSize returns the declared volume size in bytes. The backup boot
// sector lives in the sector immediately after this range.
func (b *BootSector) VolumeSize() int64 {
	return int64(b.TotalSectors) * int64(b.BytesPerSector)
}

func pow2(v uint32) bool { return v != 0 && v&(v-1) == 0 }

// ParseBootSector validates and decodes an NTFS boot sector.
func ParseBootSector(b []byte) (*BootSector, error) {
	if len(b) < 512 {
		return nil, errors.New("ntfs: boot sector too short")
	}
	if string(b[3:11]) != "NTFS    " {
		return nil, errors.New("ntfs: no NTFS OEM ID")
	}
	if b[510] != 0x55 || b[511] != 0xAA {
		return nil, errors.New("ntfs: missing 0x55AA signature")
	}
	bs := &BootSector{
		BytesPerSector: uint32(binary.LittleEndian.Uint16(b[11:])),
		TotalSectors:   binary.LittleEndian.Uint64(b[40:]),
		MFTCluster:     binary.LittleEndian.Uint64(b[48:]),
		MFTMirrCluster: binary.LittleEndian.Uint64(b[56:]),
		Serial:         binary.LittleEndian.Uint64(b[72:]),
	}
	spc := uint32(b[13])
	if spc > 0x80 {
		spc = 1 << (256 - spc) // large-cluster encoding (Windows 10 1709+)
	}
	bs.SectorsPerCluster = spc
	if !pow2(bs.BytesPerSector) || bs.BytesPerSector < 256 || bs.BytesPerSector > 4096 {
		return nil, fmt.Errorf("ntfs: bad bytes/sector %d", bs.BytesPerSector)
	}
	if !pow2(spc) || bs.ClusterSize() > 2<<20 {
		return nil, fmt.Errorf("ntfs: bad sectors/cluster %d", spc)
	}
	if bs.TotalSectors == 0 {
		return nil, errors.New("ntfs: zero total sectors")
	}
	clusters := bs.TotalSectors / uint64(spc)
	if bs.MFTCluster == 0 || bs.MFTCluster >= clusters || bs.MFTMirrCluster >= clusters {
		return nil, fmt.Errorf("ntfs: MFT cluster %d outside volume of %d clusters", bs.MFTCluster, clusters)
	}
	sizeField := func(v int8) (uint32, error) {
		if v > 0 {
			return uint32(v) * uint32(bs.ClusterSize()), nil
		}
		if v < -31 || v == 0 {
			return 0, fmt.Errorf("ntfs: bad size exponent %d", v)
		}
		return 1 << uint(-v), nil
	}
	var err error
	if bs.RecordSize, err = sizeField(int8(b[64])); err != nil {
		return nil, err
	}
	if bs.RecordSize < 512 || bs.RecordSize > 64<<10 || bs.RecordSize%fixupStride != 0 {
		return nil, fmt.Errorf("ntfs: implausible MFT record size %d", bs.RecordSize)
	}
	if bs.IndexRecordSize, err = sizeField(int8(b[68])); err != nil {
		return nil, err
	}
	return bs, nil
}
