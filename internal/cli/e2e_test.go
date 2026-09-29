package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shanurwan/barerelic/internal/evidence"
	"github.com/shanurwan/barerelic/internal/rescuemap"
	"github.com/shanurwan/barerelic/internal/testutil/fatimg"
	ntfsimg "github.com/shanurwan/barerelic/internal/testutil/ntfsimg"
)

type disk struct {
	path                string
	fatStart, ntfsStart int64
	fatDeleted          []byte
	fatDeletedOff       int64 // absolute offset of its first cluster
	ntfsDeleted         []byte
	ntfsResident        []byte
	png                 []byte
}

func rnd(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

// buildDisk writes an MBR disk: FAT16 at 1 MiB, NTFS after it.
func buildDisk(t *testing.T) *disk {
	t.Helper()
	d := &disk{fatDeleted: rnd(5000, 1), ntfsDeleted: rnd(9000, 2), ntfsResident: []byte("meeting notes: ship it\n")}

	f := fatimg.New(fatimg.FAT16)
	root := f.Root()
	f.AddFile(root, "keep me.txt", "KEEPME~1.TXT", []byte("still here"), false)
	cl, slots := f.AddFile(root, "Invoice March.pdf", "INVOIC~1.PDF", d.fatDeleted, false)
	f.Delete(slots, cl)
	// A PNG in never-allocated space, found only by carving.
	var pb bytes.Buffer
	im := image.NewRGBA(image.Rect(0, 0, 32, 32))
	for i := range im.Pix {
		im.Pix[i] = byte(i * 13)
	}
	im.Set(0, 0, color.RGBA{1, 2, 3, 255})
	if err := png.Encode(&pb, im); err != nil {
		t.Fatal(err)
	}
	d.png = pb.Bytes()
	copy(f.B[f.ClusterOffset(3000):], d.png)

	n := ntfsimg.New()
	n.Write(300, d.ntfsDeleted)
	n.Put(ntfsimg.Rec{Num: 30, Seq: 2, Attrs: [][]byte{
		ntfsimg.StdInfo(ntfsimg.Time), ntfsimg.FileName(ntfsimg.Root, "payroll.xlsx", ntfsimg.NSWin32),
		ntfsimg.Data(int64(len(d.ntfsDeleted)), ntfsimg.Run{LCN: 300, N: 3})}})
	n.Put(ntfsimg.Rec{Num: 31, Seq: 2, Attrs: [][]byte{
		ntfsimg.FileName(ntfsimg.Root, "notes.txt", ntfsimg.NSWin32), ntfsimg.Resident(ntfsimg.AttrData, "", d.ntfsResident)}})
	nb := n.Finish()

	const ss = 512
	d.fatStart = 1 << 20
	d.ntfsStart = d.fatStart + int64(len(f.B)) + (1 << 20)
	d.ntfsStart -= d.ntfsStart % (1 << 20)
	total := d.ntfsStart + int64(len(nb)) + (1 << 20)
	img := make([]byte, total)
	entry := func(i int, typ byte, start, size int64) {
		e := img[446+16*i:]
		e[4] = typ
		binary.LittleEndian.PutUint32(e[8:], uint32(start/ss))
		binary.LittleEndian.PutUint32(e[12:], uint32(size/ss))
	}
	entry(0, 0x06, d.fatStart, int64(len(f.B)))
	entry(1, 0x07, d.ntfsStart, int64(len(nb)))
	img[510], img[511] = 0x55, 0xAA
	copy(img[d.fatStart:], f.B)
	copy(img[d.ntfsStart:], nb)
	d.fatDeletedOff = d.fatStart + int64(f.ClusterOffset(cl[0]))

	d.path = filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(d.path, img, 0o644); err != nil {
		t.Fatal(err)
	}
	return d
}

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(context.Background(), append([]string{"barerelic"}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

func mustCode(t *testing.T, want int, args ...string) string {
	t.Helper()
	code, out, errs := run(t, args...)
	if code != want {
		t.Fatalf("barerelic %s: exit %d, want %d\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), code, want, out, errs)
	}
	return out
}

func readCaseFile(t *testing.T, dir, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, evidence.FilesDir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEndToEnd(t *testing.T) {
	d := buildDisk(t)
	work := t.TempDir()
	img := filepath.Join(work, "evidence.img")

	// 1. Acquire and verify the image.
	out := mustCode(t, ExitOK, "image", "--out", img, "--case", "CASE-42", "--examiner", "tester", d.path)
	if !strings.Contains(out, "sha256:") {
		t.Fatalf("image summary lacks hash:\n%s", out)
	}
	src, _ := os.ReadFile(d.path)
	dst, _ := os.ReadFile(img)
	if !bytes.Equal(src, dst) {
		t.Fatal("image differs from source")
	}
	mustCode(t, ExitOK, "verify", img)
	// Re-running on a finished image is an idempotent no-op resume.
	mustCode(t, ExitOK, "image", "--out", img, d.path)

	// 2. Probe finds both partitions and their file systems.
	var rep probeReport
	if err := json.Unmarshal([]byte(mustCode(t, ExitOK, "probe", "--json", img)), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Volumes) != 2 || rep.Volumes[0].FS == nil || rep.Volumes[0].FS.Type != "fat16" ||
		rep.Volumes[1].FS == nil || rep.Volumes[1].FS.Type != "ntfs" {
		t.Fatalf("probe volumes = %+v", rep.Volumes)
	}

	// 3. Recover deleted files from every volume.
	caseDir := filepath.Join(work, "case1")
	mustCode(t, ExitOK, "recover", "--out", caseDir, img)
	if got := readCaseFile(t, caseDir, "p1/Invoice March.pdf"); !bytes.Equal(got, d.fatDeleted) {
		t.Fatal("FAT deleted file content mismatch")
	}
	if got := readCaseFile(t, caseDir, "p2/payroll.xlsx"); !bytes.Equal(got, d.ntfsDeleted) {
		t.Fatal("NTFS deleted file content mismatch")
	}
	if got := readCaseFile(t, caseDir, "p2/notes.txt"); !bytes.Equal(got, d.ntfsResident) {
		t.Fatal("NTFS resident deleted file content mismatch")
	}
	if _, err := os.Stat(filepath.Join(caseDir, evidence.FilesDir, "p1", "keep me.txt")); err == nil {
		t.Fatal("live file recovered without --all")
	}
	mustCode(t, ExitOK, "verify", caseDir)

	// Evidence is tamper-evident.
	os.WriteFile(filepath.Join(caseDir, evidence.FilesDir, "p2", "notes.txt"), []byte("forged"), 0o644)
	mustCode(t, ExitPartial, "verify", caseDir)

	// A case directory is never reused.
	mustCode(t, ExitFailure, "recover", "--out", caseDir, img)

	// 4. Dry run lists without writing.
	out = mustCode(t, ExitOK, "recover", "--dry-run", "--all", "--partition", "1", img)
	if !strings.Contains(out, "keep me.txt") || !strings.Contains(out, "Invoice March.pdf") {
		t.Fatalf("dry-run listing incomplete:\n%s", out)
	}

	// 5. Carving finds the PNG that no file system references.
	carveDir := filepath.Join(work, "carved")
	mustCode(t, ExitOK, "carve", "--types", "png", "--out", carveDir, img)
	matches, _ := filepath.Glob(filepath.Join(carveDir, evidence.FilesDir, "carved", "png", "*.png"))
	if len(matches) != 1 {
		t.Fatalf("carved %d PNGs, want 1", len(matches))
	}
	if got, _ := os.ReadFile(matches[0]); !bytes.Equal(got, d.png) {
		t.Fatal("carved PNG mismatch")
	}

	// 6. A rescue map marking the deleted file's first sector unreadable
	// downgrades it to low confidence and makes the run partial.
	m := rescuemap.New(int64(len(src)))
	m.Set(0, int64(len(src)), rescuemap.Finished)
	m.Set(d.fatDeletedOff, 512, rescuemap.BadSector)
	mapPath := filepath.Join(work, "evidence.map")
	if err := m.Save(mapPath); err != nil {
		t.Fatal(err)
	}
	caseDir2 := filepath.Join(work, "case2")
	mustCode(t, ExitPartial, "recover", "--partition", "1", "--map", mapPath, "--out", caseDir2, img)
	jb, _ := os.ReadFile(filepath.Join(caseDir2, evidence.JournalFile))
	entries, _, err := evidence.ReadJournal(bytes.NewReader(jb))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		var a evidence.Artifact
		if e.Kind == "artifact" && json.Unmarshal(e.Data, &a) == nil && strings.HasSuffix(a.Path, "Invoice March.pdf") {
			found = a.Confidence == evidence.Low && a.Unreadable == 512
		}
	}
	if !found {
		t.Fatal("artifact over unreadable sectors was not flagged")
	}
}

func TestSafetyAndUsage(t *testing.T) {
	d := buildDisk(t)
	// Output onto the evidence itself is refused.
	mustCode(t, ExitFailure, "image", "--out", d.path, d.path)
	// An image without a map is never overwritten.
	stray := filepath.Join(t.TempDir(), "stray.img")
	os.WriteFile(stray, []byte("x"), 0o644)
	mustCode(t, ExitFailure, "image", "--out", stray, d.path)

	mustCode(t, ExitUsage)
	mustCode(t, ExitUsage, "nonsense")
	mustCode(t, ExitUsage, "recover", d.path)
	mustCode(t, ExitUsage, "carve", "--types", "nope", "--out", filepath.Join(t.TempDir(), "c"), d.path)
	mustCode(t, ExitOK, "version")
	mustCode(t, ExitOK, "carve", "--list-types")
}

// TestWriteDemoDisk writes the synthetic evidence disk used by the end-to-end
// test to $BARERELIC_DEMO_DISK, for demos and manual exploration
// (see `make demo`). It is skipped unless the variable is set.
func TestWriteDemoDisk(t *testing.T) {
	dst := os.Getenv("BARERELIC_DEMO_DISK")
	if dst == "" {
		t.Skip("BARERELIC_DEMO_DISK not set")
	}
	b, err := os.ReadFile(buildDisk(t).path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHash(t *testing.T) {
	p := filepath.Join(t.TempDir(), "abc")
	os.WriteFile(p, []byte("abc"), 0o644)
	out := mustCode(t, ExitOK, "hash", p)
	for _, want := range []string{
		"900150983cd24fb0d6963f7d28e17f72",
		"a9993e364706816aba3e25717850c26c9cd0d89d",
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("hash output missing %s:\n%s", want, out)
		}
	}
}
