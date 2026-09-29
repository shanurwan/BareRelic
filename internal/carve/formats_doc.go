package carve

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// validatePDF finds the end of a PDF. PDFs have no length field and may be
// incrementally updated (several %%EOF markers), so the last %%EOF before
// either another PDF header or a quiet window is taken. This is heuristic.
func validatePDF(s *Src) (Result, error) {
	h, err := s.At(0, 8)
	if err != nil || !(h[5] >= '1' && h[5] <= '2' && h[6] == '.') {
		return invalid()
	}
	const block = 1 << 20
	const quiet = 4 << 20 // stop this far past the last %%EOF
	eof := []byte("%%EOF")
	hdr := []byte("%PDF-")
	buf := make([]byte, block+8)
	lastEnd := int64(-1)
	for p := int64(0); p < s.limit; p += block {
		n, _ := s.r.ReadAt(buf[:min(int64(len(buf)), s.limit-p)], s.off+p)
		if n == 0 {
			break
		}
		chunk := buf[:n]
		stop := len(chunk)
		if i := bytes.Index(chunk[min(len(chunk), boolInt(p == 0)*5):], hdr); i >= 0 {
			stop = i + boolInt(p == 0)*5 // a new document begins: do not run into it
		}
		for i := 0; ; {
			j := bytes.Index(chunk[i:stop], eof)
			if j < 0 {
				break
			}
			end := p + int64(i+j+len(eof))
			for k := int(end - p); k < n && k < int(end-p)+2 && (chunk[k] == '\r' || chunk[k] == '\n'); k++ {
				end++
			}
			if end <= s.limit {
				lastEnd = end
			}
			i += j + len(eof)
		}
		if stop < len(chunk) || (lastEnd >= 0 && p+block-lastEnd > quiet) {
			break
		}
	}
	if lastEnd < 0 {
		return invalid()
	}
	return Result{Length: lastEnd, Validation: Heuristic,
		Notes: []string{"PDF end located by the last %%EOF marker; trailing incremental updates beyond a gap may be missed"}}, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// validateSQLite uses the in-header database size, trusted only when the
// header's version-valid-for counter matches its change counter.
func validateSQLite(s *Src) (Result, error) {
	h, err := s.At(0, 100)
	if err != nil {
		return invalid()
	}
	ps := int64(binary.BigEndian.Uint16(h[16:]))
	if ps == 1 {
		ps = 65536
	}
	if ps < 512 || ps&(ps-1) != 0 || h[18] < 1 || h[18] > 2 || h[19] < 1 || h[19] > 2 ||
		h[21] != 64 || h[22] != 32 || h[23] != 32 {
		return invalid()
	}
	pages := int64(binary.BigEndian.Uint32(h[28:]))
	if pages == 0 || binary.BigEndian.Uint32(h[24:]) != binary.BigEndian.Uint32(h[92:]) {
		return invalid() // legacy header without a trustworthy size
	}
	if pages*ps > s.limit {
		return invalid()
	}
	return Result{Length: pages * ps, Validation: Structural}, nil
}

const (
	oleFree      = 0xFFFFFFFF
	oleEndChain  = 0xFFFFFFFE
	oleFATSect   = 0xFFFFFFFD
	oleDIFATSect = 0xFFFFFFFC
)

// validateOLE (Compound File Binary: .doc/.xls/.ppt/.msg) sizes the file by
// the highest sector in use according to the FAT, then names the subtype
// from the root directory's stream names.
func validateOLE(s *Src) (Result, error) {
	h, err := s.At(0, 512)
	if err != nil {
		return invalid()
	}
	major := binary.LittleEndian.Uint16(h[26:])
	shift := binary.LittleEndian.Uint16(h[30:])
	if binary.LittleEndian.Uint16(h[28:]) != 0xFFFE || binary.LittleEndian.Uint16(h[32:]) != 6 ||
		!(major == 3 && shift == 9 || major == 4 && shift == 12) {
		return invalid()
	}
	ss := int64(1) << shift
	numFAT := int64(binary.LittleEndian.Uint32(h[44:]))
	if numFAT == 0 || numFAT*ss > s.limit {
		return invalid()
	}
	fatSectors := make([]uint32, 0, numFAT)
	for i := 0; i < 109 && int64(len(fatSectors)) < numFAT; i++ {
		fatSectors = append(fatSectors, binary.LittleEndian.Uint32(h[76+4*i:]))
	}
	difat := binary.LittleEndian.Uint32(h[68:])
	for guard := 0; int64(len(fatSectors)) < numFAT && difat < oleDIFATSect && guard < 1<<16; guard++ {
		d, err := s.At((int64(difat)+1)*ss, int(ss))
		if err != nil {
			return invalid()
		}
		for i := int64(0); i < ss/4-1 && int64(len(fatSectors)) < numFAT; i++ {
			fatSectors = append(fatSectors, binary.LittleEndian.Uint32(d[4*i:]))
		}
		difat = binary.LittleEndian.Uint32(d[ss-4:])
	}
	if int64(len(fatSectors)) < numFAT {
		return invalid()
	}
	maxUsed := int64(-1)
	perSector := ss / 4
	for k, sec := range fatSectors {
		if sec >= oleDIFATSect {
			return invalid()
		}
		d, err := s.At((int64(sec)+1)*ss, int(ss))
		if err != nil {
			return invalid()
		}
		for i := int64(0); i < perSector; i++ {
			if binary.LittleEndian.Uint32(d[4*i:]) != oleFree {
				maxUsed = int64(k)*perSector + i
			}
		}
	}
	if maxUsed < 0 {
		return invalid()
	}
	length := (maxUsed + 2) * ss
	if length > s.limit {
		return invalid()
	}
	return Result{Length: length, Ext: oleSubtype(s, h, ss), Validation: Structural}, nil
}

func oleSubtype(s *Src, h []byte, ss int64) string {
	dir := binary.LittleEndian.Uint32(h[48:])
	d, err := s.At((int64(dir)+1)*ss, int(ss))
	if err != nil {
		return "ole"
	}
	var names []string
	for e := 0; e+128 <= len(d); e += 128 {
		nl := int(binary.LittleEndian.Uint16(d[e+64:]))
		if nl < 2 || nl > 64 {
			continue
		}
		u := make([]uint16, nl/2-1)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(d[e+2*i:])
		}
		names = append(names, string(utf16.Decode(u)))
	}
	all := strings.Join(names, "\x00")
	switch {
	case strings.Contains(all, "WordDocument"):
		return "doc"
	case strings.Contains(all, "Workbook") || strings.Contains(all, "Book"):
		return "xls"
	case strings.Contains(all, "PowerPoint Document"):
		return "ppt"
	case strings.Contains(all, "__substg1.0_"):
		return "msg"
	case strings.Contains(all, "Catalog"):
		return "db" // Thumbs.db
	}
	return "ole"
}
