package carve

import (
	"encoding/binary"
	"hash/crc32"
	"io"
)

func isSOF(m byte) bool {
	return m >= 0xC0 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC
}

// validateJPEG walks JPEG segments. Embedded thumbnails (inside APP1 Exif)
// are skipped by segment length, so the outer image's EOI is found. After
// each SOS the entropy-coded data is scanned for the next real marker.
func validateJPEG(s *Src) (Result, error) {
	q := s.Seq(2)
	sawSOF, sawSOS := false, false
	var m byte
	pending := false
	for {
		if !pending {
			b, err := q.ReadByte()
			if err != nil || b != 0xFF {
				return invalid()
			}
			if m, err = q.ReadByte(); err != nil {
				return invalid()
			}
		}
		pending = false
		for m == 0xFF { // fill bytes
			var err error
			if m, err = q.ReadByte(); err != nil {
				return invalid()
			}
		}
		switch {
		case m == 0xD9:
			if !sawSOS {
				return invalid()
			}
			return Result{Length: q.Pos(), Validation: Structural}, nil
		case m >= 0xD0 && m <= 0xD7, m == 0x01:
			continue
		case m == 0xD8 || m == 0x00:
			return invalid()
		}
		l, err := q.u16be()
		if err != nil || l < 2 {
			return invalid()
		}
		if isSOF(m) {
			sawSOF = true
		}
		if err := q.Skip(int64(l) - 2); err != nil {
			return invalid()
		}
		if m != 0xDA {
			continue
		}
		if !sawSOF {
			return invalid()
		}
		sawSOS = true
		// Entropy-coded segment: 0xFF00 is a stuffed byte, 0xFFD0-D7 are
		// restart markers; any other 0xFFxx is the next marker.
		for {
			b, err := q.ReadByte()
			if err != nil {
				return invalid()
			}
			if b != 0xFF {
				continue
			}
			n, err := q.ReadByte()
			for err == nil && n == 0xFF {
				n, err = q.ReadByte()
			}
			if err != nil {
				return invalid()
			}
			if n == 0x00 || (n >= 0xD0 && n <= 0xD7) {
				continue
			}
			m, pending = n, true
			break
		}
	}
}

// validatePNG verifies the CRC of every chunk from IHDR to IEND.
func validatePNG(s *Src) (Result, error) {
	q := s.Seq(8)
	first := true
	for {
		hdr, err := q.Full(8)
		if err != nil {
			return invalid()
		}
		n := binary.BigEndian.Uint32(hdr)
		typ := hdr[4:8]
		if n > 0x7FFFFFFF {
			return invalid()
		}
		for _, c := range typ {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
				return invalid()
			}
		}
		if first && (string(typ) != "IHDR" || n != 13) {
			return invalid()
		}
		first = false
		h := crc32.NewIEEE()
		h.Write(typ)
		if _, err := io.CopyN(h, q, int64(n)); err != nil {
			return invalid()
		}
		crc, err := q.Full(4)
		if err != nil || binary.BigEndian.Uint32(crc) != h.Sum32() {
			return invalid()
		}
		if string(typ) == "IEND" {
			return Result{Length: q.Pos(), Validation: Structural}, nil
		}
	}
}

func skipSubBlocks(q *Seq) error {
	for {
		n, err := q.ReadByte()
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		if err := q.Skip(int64(n)); err != nil {
			return err
		}
	}
}

// validateGIF walks the GIF block structure to the trailer.
func validateGIF(s *Src) (Result, error) {
	hdr, err := s.At(0, 13)
	if err != nil || (string(hdr[:6]) != "GIF87a" && string(hdr[:6]) != "GIF89a") {
		return invalid()
	}
	if binary.LittleEndian.Uint16(hdr[6:]) == 0 || binary.LittleEndian.Uint16(hdr[8:]) == 0 {
		return invalid()
	}
	q := s.Seq(13)
	if hdr[10]&0x80 != 0 {
		if err := q.Skip(3 << (hdr[10]&7 + 1)); err != nil {
			return invalid()
		}
	}
	images := 0
	for {
		b, err := q.ReadByte()
		if err != nil {
			return invalid()
		}
		switch b {
		case 0x3B:
			if images == 0 {
				return invalid()
			}
			return Result{Length: q.Pos(), Validation: Structural}, nil
		case 0x21:
			if _, err := q.ReadByte(); err != nil {
				return invalid()
			}
			if err := skipSubBlocks(q); err != nil {
				return invalid()
			}
		case 0x2C:
			d, err := q.Full(9)
			if err != nil {
				return invalid()
			}
			if d[8]&0x80 != 0 {
				if err := q.Skip(3 << (d[8]&7 + 1)); err != nil {
					return invalid()
				}
			}
			lzw, err := q.ReadByte()
			if err != nil || lzw < 1 || lzw > 12 {
				return invalid()
			}
			if err := skipSubBlocks(q); err != nil {
				return invalid()
			}
			images++
		default:
			return invalid()
		}
	}
}

// validateBMP checks header consistency; BMP has no footer, so the declared
// file size is authoritative once the header is plausible.
func validateBMP(s *Src) (Result, error) {
	h, err := s.At(0, 34)
	if err != nil {
		return invalid()
	}
	size := int64(binary.LittleEndian.Uint32(h[2:]))
	dataOff := int64(binary.LittleEndian.Uint32(h[10:]))
	dib := binary.LittleEndian.Uint32(h[14:])
	if binary.LittleEndian.Uint32(h[6:]) != 0 {
		return invalid()
	}
	switch dib {
	case 12, 40, 52, 56, 64, 108, 124:
	default:
		return invalid()
	}
	var w, hgt int32
	var planes, bpp uint16
	if dib == 12 {
		w, hgt = int32(binary.LittleEndian.Uint16(h[18:])), int32(binary.LittleEndian.Uint16(h[20:]))
		planes, bpp = binary.LittleEndian.Uint16(h[22:]), binary.LittleEndian.Uint16(h[24:])
	} else {
		w, hgt = int32(binary.LittleEndian.Uint32(h[18:])), int32(binary.LittleEndian.Uint32(h[22:]))
		planes, bpp = binary.LittleEndian.Uint16(h[26:]), binary.LittleEndian.Uint16(h[28:])
	}
	if hgt < 0 {
		hgt = -hgt
	}
	switch bpp {
	case 1, 4, 8, 16, 24, 32:
	default:
		return invalid()
	}
	if planes != 1 || w <= 0 || hgt <= 0 || w > 1<<16 || hgt > 1<<16 {
		return invalid()
	}
	if dataOff < 14+int64(dib) || dataOff >= size || size > s.limit {
		return invalid()
	}
	// For uncompressed bitmaps the pixel array size is exact.
	rowBytes := (int64(w)*int64(bpp) + 31) / 32 * 4
	const biRGB = 0
	if dib != 12 && binary.LittleEndian.Uint32(h[30:]) == biRGB && dataOff+rowBytes*int64(hgt) > size {
		return invalid()
	}
	return Result{Length: size, Validation: Structural}, nil
}
