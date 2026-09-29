package carve

import (
	"compress/gzip"
	"encoding/binary"
	"hash/crc32"
	"io"
	"strings"
)

const (
	zipLFH      = 0x04034b50
	zipCDH      = 0x02014b50
	zipEOCD     = 0x06054b50
	zipEOCD64   = 0x06064b50
	zipLoc64    = 0x07064b50
	zipDD       = 0x08074b50
	zipDigSig   = 0x05054b50
	zipMaxWalk  = 1 << 20 // records
	zipFallback = 256 << 20
)

// validateZIP walks local headers, the central directory and the end
// record, checking that the central directory starts where the end record
// says it does. Archives written in streaming mode (data descriptors, sizes
// unknown in the local header) fall back to locating the end record.
func validateZIP(s *Src) (Result, error) {
	var p int64
	firstCD := int64(-1)
	var names []string
	var firstName string
	var firstData int64 = -1
	var firstMethod uint32
	for n := 0; n < zipMaxWalk; n++ {
		sig, err := s.u32le(p)
		if err != nil {
			return invalid()
		}
		switch sig {
		case zipLFH:
			h, err := s.At(p, 30)
			if err != nil {
				return invalid()
			}
			flags := binary.LittleEndian.Uint16(h[6:])
			method := uint32(binary.LittleEndian.Uint16(h[8:]))
			csize := int64(binary.LittleEndian.Uint32(h[18:]))
			nameLen := int64(binary.LittleEndian.Uint16(h[26:]))
			extraLen := int64(binary.LittleEndian.Uint16(h[28:]))
			if nameLen == 0 || nameLen > 4096 || !zipMethodOK(method) {
				return invalid()
			}
			if firstData < 0 {
				nb, err := s.At(p+30, int(nameLen))
				if err != nil {
					return invalid()
				}
				firstName, firstData, firstMethod = string(nb), p+30+nameLen+extraLen, method
			}
			if csize == 0xFFFFFFFF {
				if csize, err = zip64Size(s, p+30+nameLen, extraLen); err != nil {
					return invalid()
				}
			}
			if flags&0x08 != 0 {
				return zipByEOCD(s, firstName, firstData, firstMethod)
			}
			p += 30 + nameLen + extraLen + csize
		case zipCDH:
			h, err := s.At(p, 46)
			if err != nil {
				return invalid()
			}
			if firstCD < 0 {
				firstCD = p
			}
			nameLen := int64(binary.LittleEndian.Uint16(h[28:]))
			if len(names) < 256 {
				if nb, err := s.At(p+46, int(nameLen)); err == nil {
					names = append(names, string(nb))
				}
			}
			p += 46 + nameLen + int64(binary.LittleEndian.Uint16(h[30:])) + int64(binary.LittleEndian.Uint16(h[32:]))
		case zipEOCD:
			h, err := s.At(p, 22)
			if err != nil {
				return invalid()
			}
			cdOff := int64(binary.LittleEndian.Uint32(h[16:]))
			if firstCD < 0 || (cdOff != 0xFFFFFFFF && cdOff != firstCD) {
				return invalid()
			}
			end := p + 22 + int64(binary.LittleEndian.Uint16(h[20:]))
			return Result{Length: end, Ext: zipSubtype(s, firstName, firstData, firstMethod, names), Validation: Structural}, nil
		case zipEOCD64:
			size, err := s.u64le(p + 4)
			if err != nil || size > 1<<20 {
				return invalid()
			}
			p += 12 + int64(size)
		case zipLoc64:
			p += 20
		case zipDD:
			p += 16
		case zipDigSig:
			l, err := s.u16le(p + 4)
			if err != nil {
				return invalid()
			}
			p += 6 + int64(l)
		default:
			return invalid()
		}
	}
	return invalid()
}

func zipMethodOK(m uint32) bool {
	switch m {
	case 0, 1, 6, 8, 9, 12, 14, 93, 95, 98, 99:
		return true
	}
	return false
}

func zip64Size(s *Src, extra, extraLen int64) (int64, error) {
	for p := extra; p+4 <= extra+extraLen; {
		id, _ := s.u16le(p)
		l, err := s.u16le(p + 2)
		if err != nil {
			return 0, err
		}
		if id == 0x0001 && l >= 16 {
			v, err := s.u64le(p + 4 + 8) // [uncompressed][compressed]
			return int64(v), err
		}
		p += 4 + int64(l)
	}
	return 0, ErrInvalid
}

// zipByEOCD locates the end record and accepts it only if the central
// directory it describes ends exactly where the end record begins.
func zipByEOCD(s *Src, firstName string, firstData int64, method uint32) (Result, error) {
	var from int64
	for {
		e, err := s.findForward([]byte("PK\x05\x06"), from, zipFallback)
		if err != nil {
			return invalid()
		}
		h, err := s.At(e, 22)
		if err != nil {
			return invalid()
		}
		cdSize := int64(binary.LittleEndian.Uint32(h[12:]))
		cdOff := int64(binary.LittleEndian.Uint32(h[16:]))
		if cdOff+cdSize == e {
			var names []string
			for p := cdOff; p < e && len(names) < 256; {
				hdr, err := s.At(p, 46)
				if err != nil || binary.LittleEndian.Uint32(hdr) != zipCDH {
					break
				}
				nl := int64(binary.LittleEndian.Uint16(hdr[28:]))
				if nb, err := s.At(p+46, int(nl)); err == nil {
					names = append(names, string(nb))
				}
				p += 46 + nl + int64(binary.LittleEndian.Uint16(hdr[30:])) + int64(binary.LittleEndian.Uint16(hdr[32:]))
			}
			end := e + 22 + int64(binary.LittleEndian.Uint16(h[20:]))
			return Result{Length: end, Ext: zipSubtype(s, firstName, firstData, method, names), Validation: Structural,
				Notes: []string{"streamed ZIP (data descriptors); end located via end-of-central-directory record"}}, nil
		}
		from = e + 4
	}
}

// zipSubtype recognises container formats built on ZIP.
func zipSubtype(s *Src, firstName string, firstData int64, method uint32, names []string) string {
	if firstName == "mimetype" && method == 0 {
		if b, err := s.At(firstData, 64); err == nil {
			mt := string(b)
			switch {
			case strings.HasPrefix(mt, "application/vnd.oasis.opendocument.text"):
				return "odt"
			case strings.HasPrefix(mt, "application/vnd.oasis.opendocument.spreadsheet"):
				return "ods"
			case strings.HasPrefix(mt, "application/vnd.oasis.opendocument.presentation"):
				return "odp"
			case strings.HasPrefix(mt, "application/epub+zip"):
				return "epub"
			}
		}
	}
	has := func(prefix string) bool {
		for _, n := range names {
			if strings.HasPrefix(n, prefix) {
				return true
			}
		}
		return false
	}
	switch {
	case has("[Content_Types].xml") && has("word/"):
		return "docx"
	case has("[Content_Types].xml") && has("xl/"):
		return "xlsx"
	case has("[Content_Types].xml") && has("ppt/"):
		return "pptx"
	case has("AndroidManifest.xml"):
		return "apk"
	case has("META-INF/MANIFEST.MF"):
		return "jar"
	}
	return "zip"
}

// byteCounter counts bytes consumed through ReadByte/Read. It implements
// io.ByteReader so compress/flate never reads ahead of the stream's end.
type byteCounter struct{ q *Seq }

func (b byteCounter) Read(p []byte) (int, error) { return b.q.Read(p) }
func (b byteCounter) ReadByte() (byte, error)    { return b.q.ReadByte() }

// validateGzip inflates the member and verifies its CRC-32 and length
// trailer (compress/gzip does both), yielding the exact compressed length.
func validateGzip(s *Src) (Result, error) {
	h, err := s.At(0, 10)
	if err != nil || h[3]&0xE0 != 0 {
		return invalid()
	}
	q := s.Seq(0)
	zr, err := gzip.NewReader(byteCounter{q})
	if err != nil {
		return invalid()
	}
	zr.Multistream(false)
	// Bound work on decompression bombs: 64x the carve limit.
	if _, err := io.Copy(io.Discard, io.LimitReader(zr, s.limit*64)); err != nil {
		return invalid()
	}
	if _, err := zr.Read(make([]byte, 1)); err != io.EOF {
		return invalid() // limit hit before the trailer was verified
	}
	res := Result{Length: q.Pos(), Validation: Structural}
	if zr.Name != "" {
		res.Notes = append(res.Notes, "original name: "+zr.Name)
	}
	return res, nil
}

// validate7z checks the start-header CRC and the next-header CRC.
func validate7z(s *Src) (Result, error) {
	h, err := s.At(0, 32)
	if err != nil || h[6] != 0 {
		return invalid()
	}
	if crc32.ChecksumIEEE(h[12:32]) != binary.LittleEndian.Uint32(h[8:]) {
		return invalid()
	}
	nextOff := int64(binary.LittleEndian.Uint64(h[12:]))
	nextSize := int64(binary.LittleEndian.Uint64(h[20:]))
	if nextOff < 0 || nextSize <= 0 || nextSize > 64<<20 || 32+nextOff+nextSize > s.limit {
		return invalid()
	}
	nh, err := s.At(32+nextOff, int(nextSize))
	if err != nil || crc32.ChecksumIEEE(nh) != binary.LittleEndian.Uint32(h[28:]) {
		return invalid()
	}
	return Result{Length: 32 + nextOff + nextSize, Validation: Structural}, nil
}
