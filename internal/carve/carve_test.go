package carve

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"math/rand"
	"testing"
	"unicode/utf16"

	"github.com/shanurwan/barerelic/internal/testutil"
)

func testImage(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x * 7), uint8(y * 3), uint8(x ^ y), 255})
		}
	}
	return img
}

func mkJPEG(t *testing.T, w, h int) []byte {
	var b bytes.Buffer
	if err := jpeg.Encode(&b, testImage(w, h), &jpeg.Options{Quality: 80}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// mkJPEGWithThumbnail inserts an APP1 segment carrying a complete JPEG, the
// way cameras embed Exif thumbnails. The carver must not stop at its EOI.
func mkJPEGWithThumbnail(t *testing.T) []byte {
	main := mkJPEG(t, 120, 90)
	thumb := mkJPEG(t, 16, 12)
	app1 := append([]byte("Exif\x00\x00"), thumb...)
	seg := []byte{0xFF, 0xE1, 0, 0}
	binary.BigEndian.PutUint16(seg[2:], uint16(len(app1)+2))
	seg = append(seg, app1...)
	return append(append(append([]byte(nil), main[:2]...), seg...), main[2:]...)
}

func mkPNG(t *testing.T) []byte {
	var b bytes.Buffer
	if err := png.Encode(&b, testImage(64, 48)); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func mkGIF(t *testing.T) []byte {
	pal := color.Palette{color.Black, color.White, color.RGBA{255, 0, 0, 255}, color.RGBA{0, 0, 255, 255}}
	g := &gif.GIF{LoopCount: 0}
	for f := 0; f < 3; f++ {
		img := image.NewPaletted(image.Rect(0, 0, 40, 30), pal)
		for i := range img.Pix {
			img.Pix[i] = uint8((i + f) % 4)
		}
		g.Image = append(g.Image, img)
		g.Delay = append(g.Delay, 10)
	}
	var b bytes.Buffer
	if err := gif.EncodeAll(&b, g); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func mkBMP() []byte {
	const w, h = 10, 4
	row := (w*24 + 31) / 32 * 4
	size := 54 + row*h
	b := make([]byte, size)
	copy(b, "BM")
	binary.LittleEndian.PutUint32(b[2:], uint32(size))
	binary.LittleEndian.PutUint32(b[10:], 54)
	binary.LittleEndian.PutUint32(b[14:], 40)
	binary.LittleEndian.PutUint32(b[18:], w)
	binary.LittleEndian.PutUint32(b[22:], h)
	binary.LittleEndian.PutUint16(b[26:], 1)
	binary.LittleEndian.PutUint16(b[28:], 24)
	for i := 54; i < size; i++ {
		b[i] = byte(i)
	}
	return b
}

func mkDOCX(t *testing.T, streamed bool) []byte {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, f := range []struct{ name, body string }{
		{"[Content_Types].xml", "<Types/>"},
		{"word/document.xml", "<w:document>" + string(bytes.Repeat([]byte("hello "), 400)) + "</w:document>"},
	} {
		var w interface{ Write([]byte) (int, error) }
		var err error
		if streamed {
			w, err = zw.Create(f.name) // sets the data-descriptor flag
		} else {
			w, err = zw.CreateRaw(&zip.FileHeader{Name: f.name, Method: zip.Store, CRC32: crc32.ChecksumIEEE([]byte(f.body)),
				CompressedSize64: uint64(len(f.body)), UncompressedSize64: uint64(len(f.body))})
		}
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(f.body))
	}
	zw.SetComment("carved")
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func mkGzip(t *testing.T) []byte {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Name = "access.log"
	zw.Write(bytes.Repeat([]byte("GET /index.html 200\n"), 500))
	zw.Close()
	return b.Bytes()
}

func mk7z() []byte {
	next := []byte{0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x00, 0x00}
	packed := bytes.Repeat([]byte{0xAB}, 100)
	h := make([]byte, 32)
	copy(h, []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 4})
	binary.LittleEndian.PutUint64(h[12:], uint64(len(packed)))
	binary.LittleEndian.PutUint64(h[20:], uint64(len(next)))
	binary.LittleEndian.PutUint32(h[28:], crc32.ChecksumIEEE(next))
	binary.LittleEndian.PutUint32(h[8:], crc32.ChecksumIEEE(h[12:32]))
	return append(append(h, packed...), next...)
}

func mkSQLite() []byte {
	const ps, pages = 1024, 3
	b := make([]byte, ps*pages)
	copy(b, "SQLite format 3\x00")
	binary.BigEndian.PutUint16(b[16:], ps)
	b[18], b[19], b[21], b[22], b[23] = 1, 1, 64, 32, 32
	binary.BigEndian.PutUint32(b[24:], 7)
	binary.BigEndian.PutUint32(b[28:], pages)
	binary.BigEndian.PutUint32(b[92:], 7)
	return b
}

func mkOLE() []byte {
	const ss = 512
	b := make([]byte, 4*ss) // header + FAT + directory + one data sector
	copy(b, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	binary.LittleEndian.PutUint16(b[24:], 0x3E)
	binary.LittleEndian.PutUint16(b[26:], 3)
	binary.LittleEndian.PutUint16(b[28:], 0xFFFE)
	binary.LittleEndian.PutUint16(b[30:], 9)
	binary.LittleEndian.PutUint16(b[32:], 6)
	binary.LittleEndian.PutUint32(b[44:], 1)           // one FAT sector
	binary.LittleEndian.PutUint32(b[48:], 1)           // directory at sector 1
	binary.LittleEndian.PutUint32(b[68:], oleEndChain) // no DIFAT sectors
	for i := 0; i < 109; i++ {
		binary.LittleEndian.PutUint32(b[76+4*i:], oleFree)
	}
	binary.LittleEndian.PutUint32(b[76:], 0) // FAT lives in sector 0
	fat := b[ss : 2*ss]
	for i := 0; i < ss/4; i++ {
		binary.LittleEndian.PutUint32(fat[4*i:], oleFree)
	}
	binary.LittleEndian.PutUint32(fat[0:], oleFATSect)
	binary.LittleEndian.PutUint32(fat[4:], oleEndChain)
	binary.LittleEndian.PutUint32(fat[8:], oleEndChain)
	dir := b[2*ss : 3*ss]
	for i, name := range []string{"Root Entry", "WordDocument"} {
		u := utf16.Encode([]rune(name))
		for j, c := range u {
			binary.LittleEndian.PutUint16(dir[i*128+2*j:], c)
		}
		binary.LittleEndian.PutUint16(dir[i*128+64:], uint16(2*len(u)+2))
	}
	return b
}

func mkWAV() []byte {
	data := make([]byte, 1000)
	b := make([]byte, 44+len(data))
	copy(b, "RIFF")
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)-8))
	copy(b[8:], "WAVEfmt ")
	copy(b[36:], "data")
	copy(b[44:], data)
	return b
}

func box(typ string, payload []byte) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, uint32(8+len(payload)))
	copy(b[4:], typ)
	return append(b, payload...)
}

func mkMP4(brand string) []byte {
	out := box("ftyp", append([]byte(brand), 0, 0, 0, 0))
	out = append(out, box("moov", box("mvhd", make([]byte, 100)))...)
	return append(out, box("mdat", bytes.Repeat([]byte{0x42}, 3000))...)
}

func mkPE() []byte {
	b := make([]byte, 0x600)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3C:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[0x84:], 0x14C)
	binary.LittleEndian.PutUint16(b[0x86:], 1)   // sections
	binary.LittleEndian.PutUint16(b[0x94:], 224) // optional header size
	binary.LittleEndian.PutUint16(b[0x96:], 0x0102)
	opt := b[0x98:]
	binary.LittleEndian.PutUint16(opt, 0x10B)
	binary.LittleEndian.PutUint32(opt[60:], 0x200) // SizeOfHeaders
	sec := b[0x98+224:]
	copy(sec, ".text")
	binary.LittleEndian.PutUint32(sec[16:], 0x400) // SizeOfRawData
	binary.LittleEndian.PutUint32(sec[20:], 0x200) // PointerToRawData
	return b
}

func mkELF() []byte {
	b := make([]byte, 0x200)
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = 2, 1, 1
	binary.LittleEndian.PutUint64(b[40:], 0x100) // shoff
	binary.LittleEndian.PutUint16(b[58:], 64)
	binary.LittleEndian.PutUint16(b[60:], 4) // 4 sections -> ends at 0x200
	sh := b[0x100+64:]
	binary.LittleEndian.PutUint32(sh[4:], 1)
	binary.LittleEndian.PutUint64(sh[24:], 0x40)
	binary.LittleEndian.PutUint64(sh[32:], 0x80)
	return b
}

func mkPDF() []byte {
	return []byte("%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n" +
		"2 0 obj << /Incremental true >> endobj\ntrailer << /Prev 0 >>\n%%EOF\r\n")
}

type planted struct {
	name string
	ext  string
	data []byte
	off  int64
}

func corpus(t *testing.T) ([]byte, []planted) {
	files := []planted{
		{name: "jpeg", ext: "jpg", data: mkJPEGWithThumbnail(t)},
		{name: "png", ext: "png", data: mkPNG(t)},
		{name: "gif", ext: "gif", data: mkGIF(t)},
		{name: "bmp", ext: "bmp", data: mkBMP()},
		{name: "zip", ext: "docx", data: mkDOCX(t, false)},
		{name: "zip", ext: "docx", data: mkDOCX(t, true)},
		{name: "gzip", ext: "gz", data: mkGzip(t)},
		{name: "7z", ext: "7z", data: mk7z()},
		{name: "sqlite", ext: "sqlite", data: mkSQLite()},
		{name: "ole", ext: "doc", data: mkOLE()},
		{name: "riff", ext: "wav", data: mkWAV()},
		{name: "isobmff", ext: "mov", data: mkMP4("qt  ")},
		{name: "isobmff", ext: "mp4", data: mkMP4("isom")},
		{name: "pe", ext: "exe", data: mkPE()},
		{name: "elf", ext: "elf", data: mkELF()},
		{name: "pdf", ext: "pdf", data: mkPDF()},
	}
	rng := rand.New(rand.NewSource(42))
	var disk []byte
	for i := range files {
		// Random filler between files, sector aligned.
		gap := make([]byte, 512*(1+rng.Intn(8)))
		rng.Read(gap)
		disk = append(disk, gap...)
		files[i].off = int64(len(disk))
		disk = append(disk, files[i].data...)
		if pad := len(disk) % 512; pad != 0 {
			disk = append(disk, make([]byte, 512-pad)...)
		}
	}
	return append(disk, make([]byte, 4096)...), files
}

func TestScanRecoversEveryFormat(t *testing.T) {
	disk, files := corpus(t)
	var got []Match
	st, err := Scan(context.Background(), bytes.NewReader(disk), int64(len(disk)), Options{}, func(m Match) error {
		got = append(got, m)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	byOff := map[int64]Match{}
	for _, m := range got {
		byOff[m.Offset] = m
	}
	for _, f := range files {
		m, ok := byOff[f.off]
		if !ok {
			t.Errorf("%s (%s) at 0x%X not carved", f.name, f.ext, f.off)
			continue
		}
		if m.Type != f.name || m.Ext != f.ext {
			t.Errorf("at 0x%X: got %s/%s, want %s/%s", f.off, m.Type, m.Ext, f.name, f.ext)
		}
		if m.Length != int64(len(f.data)) {
			t.Errorf("%s at 0x%X: length %d, want %d", f.ext, f.off, m.Length, len(f.data))
		}
	}
	if len(got) != len(files) {
		for _, m := range got {
			t.Logf("carved %s/%s at 0x%X len %d", m.Type, m.Ext, m.Offset, m.Length)
		}
		t.Errorf("carved %d files, planted %d (false positives or embedded files carved)", len(got), len(files))
	}
	if st.Scanned != int64(len(disk)) {
		t.Errorf("scanned %d of %d bytes", st.Scanned, len(disk))
	}
}

func TestNoSkipFindsEmbeddedThumbnail(t *testing.T) {
	j := mkJPEGWithThumbnail(t)
	disk := append(append([]byte(nil), j...), make([]byte, 1024)...)
	var n int
	_, err := Scan(context.Background(), bytes.NewReader(disk), int64(len(disk)),
		Options{Align: 1, NoSkip: true, Signatures: mustLookup(t, "jpeg")}, func(Match) error { n++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected outer image and thumbnail, got %d", n)
	}
}

func TestRejectsDamagedFiles(t *testing.T) {
	cases := map[string][]byte{}
	j := mkJPEG(t, 32, 32)
	cases["jpeg-truncated"] = j[:len(j)/2]
	p := mkPNG(t)
	p = append([]byte(nil), p...)
	p[40] ^= 0xFF // corrupt IDAT payload -> CRC mismatch
	cases["png-crc"] = p
	z := mkDOCX(t, false)
	cases["zip-truncated"] = z[:len(z)-30]
	g := mkGzip(t)
	g = append([]byte(nil), g...)
	g[len(g)-6] ^= 0xFF // CRC trailer
	cases["gzip-crc"] = g
	s7 := mk7z()
	s7[20] ^= 1
	cases["7z-header-crc"] = s7

	for name, data := range cases {
		disk := append(append([]byte(nil), data...), make([]byte, 4096)...)
		var n int
		Scan(context.Background(), bytes.NewReader(disk), int64(len(disk)), Options{}, func(m Match) error {
			t.Logf("%s: carved %s len %d", name, m.Type, m.Length)
			n++
			return nil
		})
		if n != 0 {
			t.Errorf("%s: damaged file accepted", name)
		}
	}
}

func TestScanSurvivesBadSectors(t *testing.T) {
	disk, files := corpus(t)
	fd := testutil.NewFaultyDisk(disk, 512)
	fd.Bad(0, 1) // inside the leading filler
	var got int
	st, err := Scan(context.Background(), fd, fd.Size(), Options{}, func(Match) error { got++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if st.ReadErrors != 2 || got != len(files) {
		t.Fatalf("read errors %d (want 2), carved %d (want %d)", st.ReadErrors, got, len(files))
	}
}

func TestLookup(t *testing.T) {
	sigs, err := Lookup([]string{"jpg", "DOCX", "mov", "jpeg"})
	if err != nil || len(sigs) != 3 {
		t.Fatalf("got %d sigs, %v", len(sigs), err)
	}
	if _, err := Lookup([]string{"nope"}); err == nil {
		t.Fatal("unknown type accepted")
	}
}

func mustLookup(t *testing.T, names ...string) []*Signature {
	s, err := Lookup(names)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func FuzzValidators(f *testing.F) {
	f.Add(mkBMP())
	f.Add(mkOLE())
	f.Add(mk7z())
	f.Add(mkMP4("isom"))
	f.Add(mkPE())
	f.Add(mkELF())
	f.Add(mkSQLite())
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, s := range Signatures {
			src := &Src{r: bytes.NewReader(b), limit: int64(len(b))}
			res, err := s.Validate(src)
			if err == nil && (res.Length <= 0 || res.Length > int64(len(b))) {
				t.Fatalf("%s: accepted length %d for %d-byte input", s.Name, res.Length, len(b))
			}
		}
	})
}
