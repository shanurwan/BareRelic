package carve

import (
	"encoding/binary"
)

// validatePE sizes a Windows executable as the furthest of: headers, section
// raw data, and the Authenticode certificate table (which is appended after
// the last section). Overlays beyond that are not included.
func validatePE(s *Src) (Result, error) {
	lfanew, err := s.u32le(0x3C)
	if err != nil || lfanew < 0x40 || lfanew > 0x10000 {
		return invalid()
	}
	pe := int64(lfanew)
	h, err := s.At(pe, 24)
	if err != nil || string(h[:4]) != "PE\x00\x00" {
		return invalid()
	}
	nsec := int64(binary.LittleEndian.Uint16(h[6:]))
	optSize := int64(binary.LittleEndian.Uint16(h[20:]))
	chars := binary.LittleEndian.Uint16(h[22:])
	if nsec == 0 || nsec > 96 || optSize < 96 {
		return invalid()
	}
	opt, err := s.At(pe+24, int(optSize))
	if err != nil {
		return invalid()
	}
	var ddOff int
	switch binary.LittleEndian.Uint16(opt) {
	case 0x10B:
		ddOff = 96
	case 0x20B:
		ddOff = 112
	default:
		return invalid()
	}
	end := int64(binary.LittleEndian.Uint32(opt[60:])) // SizeOfHeaders
	secs, err := s.At(pe+24+optSize, int(nsec*40))
	if err != nil {
		return invalid()
	}
	for i := int64(0); i < nsec; i++ {
		e := secs[i*40:]
		raw := int64(binary.LittleEndian.Uint32(e[16:]))
		ptr := int64(binary.LittleEndian.Uint32(e[20:]))
		if raw > 0 {
			end = max(end, ptr+raw)
		}
	}
	if len(opt) >= ddOff+5*8 { // data directory 4: certificate table (file offset + size)
		certOff := int64(binary.LittleEndian.Uint32(opt[ddOff+32:]))
		certLen := int64(binary.LittleEndian.Uint32(opt[ddOff+36:]))
		if certOff > 0 && certLen > 0 {
			end = max(end, certOff+certLen)
		}
	}
	if end <= pe || end > s.limit {
		return invalid()
	}
	ext := "exe"
	if chars&0x2000 != 0 {
		ext = "dll"
	}
	return Result{Length: end, Ext: ext, Validation: Structural,
		Notes: []string{"PE size from headers, sections and certificate table; appended overlay data is not included"}}, nil
}

// validateELF sizes an ELF file by its section and program header tables and
// the sections/segments they describe.
func validateELF(s *Src) (Result, error) {
	h, err := s.At(0, 64)
	if err != nil {
		return invalid()
	}
	class, data := h[4], h[5]
	if (class != 1 && class != 2) || (data != 1 && data != 2) || h[6] != 1 {
		return invalid()
	}
	var bo binary.ByteOrder = binary.LittleEndian
	if data == 2 {
		bo = binary.BigEndian
	}
	var phoff, shoff int64
	var phentsize, phnum, shentsize, shnum int64
	if class == 1 {
		phoff, shoff = int64(bo.Uint32(h[28:])), int64(bo.Uint32(h[32:]))
		phentsize, phnum = int64(bo.Uint16(h[42:])), int64(bo.Uint16(h[44:]))
		shentsize, shnum = int64(bo.Uint16(h[46:])), int64(bo.Uint16(h[48:]))
	} else {
		phoff, shoff = int64(bo.Uint64(h[32:])), int64(bo.Uint64(h[40:]))
		phentsize, phnum = int64(bo.Uint16(h[54:])), int64(bo.Uint16(h[56:]))
		shentsize, shnum = int64(bo.Uint16(h[58:])), int64(bo.Uint16(h[60:]))
	}
	if phnum > 4096 || shnum > 65535 || phoff < 0 || shoff < 0 {
		return invalid()
	}
	end := int64(52)
	if class == 2 {
		end = 64
	}
	if phnum > 0 {
		want := int64(32)
		if class == 2 {
			want = 56
		}
		if phentsize != want {
			return invalid()
		}
		end = max(end, phoff+phnum*phentsize)
		tab, err := s.At(phoff, int(phnum*phentsize))
		if err != nil {
			return invalid()
		}
		for i := int64(0); i < phnum; i++ {
			e := tab[i*phentsize:]
			var off, filesz int64
			if class == 1 {
				off, filesz = int64(bo.Uint32(e[4:])), int64(bo.Uint32(e[16:]))
			} else {
				off, filesz = int64(bo.Uint64(e[8:])), int64(bo.Uint64(e[32:]))
			}
			if off < 0 || filesz < 0 {
				return invalid()
			}
			end = max(end, off+filesz)
		}
	}
	if shnum > 0 {
		want := int64(40)
		if class == 2 {
			want = 64
		}
		if shentsize != want {
			return invalid()
		}
		end = max(end, shoff+shnum*shentsize)
		tab, err := s.At(shoff, int(shnum*shentsize))
		if err != nil {
			return invalid()
		}
		for i := int64(0); i < shnum; i++ {
			e := tab[i*shentsize:]
			var typ uint32
			var off, size int64
			if class == 1 {
				typ, off, size = bo.Uint32(e[4:]), int64(bo.Uint32(e[16:])), int64(bo.Uint32(e[20:]))
			} else {
				typ, off, size = bo.Uint32(e[4:]), int64(bo.Uint64(e[24:])), int64(bo.Uint64(e[32:]))
			}
			if typ != 8 && off >= 0 && size >= 0 { // SHT_NOBITS occupies no file space
				end = max(end, off+size)
			}
		}
	}
	if phnum == 0 && shnum == 0 {
		return invalid()
	}
	if end > s.limit {
		return invalid()
	}
	return Result{Length: end, Validation: Structural}, nil
}
