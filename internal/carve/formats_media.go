package carve

import (
	"encoding/binary"
	"strings"
)

// validateRIFF handles WAV, AVI and WebP: the RIFF size field is exact, and
// the first sub-chunk must carry a printable FourCC.
func validateRIFF(s *Src) (Result, error) {
	h, err := s.At(0, 20)
	if err != nil {
		return invalid()
	}
	size := int64(binary.LittleEndian.Uint32(h[4:])) + 8
	var ext string
	switch string(h[8:12]) {
	case "WAVE":
		ext = "wav"
	case "AVI ":
		ext = "avi"
	case "WEBP":
		ext = "webp"
	default:
		return invalid()
	}
	if !printableFourCC(h[12:16]) || size < 20 {
		return invalid()
	}
	if size%2 == 1 {
		size++
	}
	if size > s.limit {
		return invalid()
	}
	return Result{Length: size, Ext: ext, Validation: Structural}, nil
}

func printableFourCC(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

var isoTopLevel = map[string]bool{
	"ftyp": true, "moov": true, "mdat": true, "free": true, "skip": true, "wide": true,
	"uuid": true, "meta": true, "pdin": true, "moof": true, "mfra": true, "sidx": true,
	"styp": true, "prft": true, "emsg": true, "pnot": true, "PICT": true,
}

// validateISOBMFF walks top-level boxes of MP4/MOV/3GP/HEIC/AVIF files
// until an unknown box type appears, requiring ftyp first and both a moov
// (or meta, for images) and an mdat box.
func validateISOBMFF(s *Src) (Result, error) {
	var p int64
	var brand string
	seen := map[string]bool{}
	for n := 0; n < 1<<16; n++ {
		h, err := s.At(p, 8)
		if err != nil {
			break
		}
		size := int64(binary.BigEndian.Uint32(h))
		typ := string(h[4:8])
		if !isoTopLevel[typ] {
			break
		}
		hdr := int64(8)
		if size == 1 {
			big, err := s.At(p+8, 8)
			if err != nil {
				return invalid()
			}
			size, hdr = int64(binary.BigEndian.Uint64(big)), 16
		}
		if size == 0 || size < hdr || p+size > s.limit {
			break // size 0 = "to end of file", unknowable when carving
		}
		if n == 0 {
			if typ != "ftyp" || size < 16 {
				return invalid()
			}
			b, err := s.At(p+8, 4)
			if err != nil {
				return invalid()
			}
			brand = string(b)
		}
		seen[typ] = true
		p += size
	}
	if !seen["ftyp"] || !seen["mdat"] || !(seen["moov"] || seen["meta"]) {
		return invalid()
	}
	return Result{Length: p, Ext: isoExt(brand), Validation: Structural}, nil
}

func isoExt(brand string) string {
	switch {
	case brand == "qt  ":
		return "mov"
	case brand == "heic" || brand == "heix" || brand == "mif1" || brand == "msf1" || brand == "hevc":
		return "heic"
	case brand == "avif":
		return "avif"
	case strings.HasPrefix(brand, "3g"):
		return "3gp"
	case brand == "M4A " || brand == "M4B ":
		return "m4a"
	case brand == "crx ":
		return "cr3"
	}
	return "mp4"
}
