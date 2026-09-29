package fat

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"strings"
	"testing"

	"github.com/shanurwan/barerelic/internal/testutil/fatimg"
)

func payload(n int, seed int64) []byte {
	p := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(p)
	return p
}

func open(t *testing.T, b *fatimg.Image) *Volume {
	t.Helper()
	v, err := Open(bytes.NewReader(b.B), int64(len(b.B)))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func collect(t *testing.T, v *Volume, deep bool) map[string]Entry {
	t.Helper()
	got := map[string]Entry{}
	if err := v.Walk(context.Background(), WalkOptions{Deep: deep}, func(e Entry) error {
		got[e.Path] = e
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func readAll(t *testing.T, v *Volume, e Entry) ([]byte, Plan) {
	t.Helper()
	p := v.PlanFile(e)
	if !p.Recoverable {
		t.Fatalf("%s not recoverable: %v", e.Path, p.Notes)
	}
	data, err := io.ReadAll(v.Reader(p))
	if err != nil {
		t.Fatal(err)
	}
	return data, p
}

func keys(m map[string]Entry) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestLiveAndDeletedFiles(t *testing.T) {
	for _, typ := range []fatimg.Type{fatimg.FAT12, fatimg.FAT16, fatimg.FAT32} {
		t.Run(Type(typ).String(), func(t *testing.T) {
			b := fatimg.New(typ)
			root := b.Root()
			cs := b.ClusterSize()
			live := payload(3*cs+100, 1)
			frag := payload(3*cs, 2)
			gone := payload(2*cs+7, 3)
			small := payload(40, 4)
			b.AddFile(root, "Quarterly Report 2019.xlsx", "QUARTE~1.XLS", live, false)
			b.AddFile(root, "fragmented.bin", "FRAGME~1.BIN", frag, true)
			gcl, gslots := b.AddFile(root, "Wedding Photo.jpg", "WEDDIN~1.JPG", gone, false)
			scl, sslots := b.AddFile(root, "", "NOTES.TXT", small, false)
			b.Delete(gslots, gcl)
			b.Delete(sslots, scl)

			v := open(t, b)
			if v.BS.Type != Type(typ) {
				t.Fatalf("detected %v", v.BS.Type)
			}
			got := collect(t, v, false)

			e, ok := got["/Quarterly Report 2019.xlsx"]
			if !ok || e.Deleted {
				t.Fatalf("live file missing/deleted: %v", keys(got))
			}
			if data, p := readAll(t, v, e); !bytes.Equal(data, live) || p.Confidence != ConfHigh {
				t.Fatalf("live content mismatch (conf %s)", p.Confidence)
			}
			if data, _ := readAll(t, v, got["/fragmented.bin"]); !bytes.Equal(data, frag) {
				t.Fatal("fragmented live file must follow the FAT chain")
			}

			d, ok := got["/Wedding Photo.jpg"]
			if !ok || !d.Deleted {
				t.Fatalf("deleted LFN file not reconstructed; entries: %v", keys(got))
			}
			if d.ShortName != "WEDDIN~1.JPG" {
				t.Fatalf("erased first char not recovered via checksum: %q", d.ShortName)
			}
			data, p := readAll(t, v, d)
			if !bytes.Equal(data, gone) || p.Confidence != ConfMedium {
				t.Fatalf("deleted content mismatch (conf %s, notes %v)", p.Confidence, p.Notes)
			}
			if d.Modified.Year() != 2019 || d.Modified.Hour() != 10 {
				t.Fatalf("timestamp = %v", d.Modified)
			}

			s, ok := got["/_OTES.TXT"]
			if !ok || !s.Deleted {
				t.Fatalf("deleted 8.3 file missing: %v", keys(got))
			}
			if data, p := readAll(t, v, s); !bytes.Equal(data, small) || p.Confidence != ConfHigh {
				t.Fatalf("single-cluster deleted file: conf %s", p.Confidence)
			}
		})
	}
}

func TestReallocatedClustersLowerConfidence(t *testing.T) {
	b := fatimg.New(fatimg.FAT16)
	cs := b.ClusterSize()
	cl, slots := b.AddFile(b.Root(), "old.doc", "OLD.DOC", payload(2*cs, 9), false)
	b.Delete(slots, cl)
	// A new file reuses the second cluster.
	b.SetFAT(cl[1], 0xFFFF)
	copy(b.B[b.ClusterOffset(cl[1]):], bytes.Repeat([]byte{0xAA}, cs))

	v := open(t, b)
	p := v.PlanFile(collect(t, v, false)["/old.doc"])
	if p.Confidence != ConfLow || len(p.Notes) == 0 {
		t.Fatalf("expected low confidence for overwritten file, got %s %v", p.Confidence, p.Notes)
	}
}

func TestDeletedDirectoryContents(t *testing.T) {
	b := fatimg.New(fatimg.FAT32)
	dir, dcl, dslots := b.Mkdir(b.Root(), "Holiday 2015", "HOLIDA~1", b.RootCluster)
	pic := payload(b.ClusterSize()/2, 5)
	b.AddFile(dir, "beach.png", "BEACH.PNG", pic, false)
	b.Delete(dslots, []uint32{dcl})

	v := open(t, b)
	got := collect(t, v, false)
	f, ok := got["/Holiday 2015/beach.png"]
	if !ok || !f.Deleted {
		t.Fatalf("file in deleted directory not found: %v", keys(got))
	}
	if data, _ := readAll(t, v, f); !bytes.Equal(data, pic) {
		t.Fatal("content mismatch")
	}
}

func TestQuickFormatDeepScan(t *testing.T) {
	b := fatimg.New(fatimg.FAT16)
	dir, dcl, _ := b.Mkdir(b.Root(), "Documents", "DOCUME~1", 0)
	sub, _, _ := b.Mkdir(dir, "Tax", "TAX", dcl)
	thesis := payload(b.ClusterSize()+300, 6)
	tax := payload(900, 7)
	b.AddFile(dir, "thesis-final.pdf", "THESIS~1.PDF", thesis, false)
	b.AddFile(sub, "2016.csv", "2016.CSV", tax, false)
	b.QuickFormat()

	v := open(t, b)
	if len(collect(t, v, false)) != 0 {
		t.Fatal("formatted volume should look empty without deep scan")
	}
	var thesisEntry, taxEntry Entry
	got := collect(t, v, true)
	for p, e := range got {
		if strings.HasSuffix(p, "/thesis-final.pdf") {
			thesisEntry = e
		}
		if strings.HasSuffix(p, "/Tax/2016.csv") {
			taxEntry = e
		}
	}
	if !thesisEntry.Orphan || !taxEntry.Orphan {
		t.Fatalf("orphaned files not found (nested path must be preserved): %v", keys(got))
	}
	if data, _ := readAll(t, v, thesisEntry); !bytes.Equal(data, thesis) {
		t.Fatal("thesis content mismatch")
	}
	if data, _ := readAll(t, v, taxEntry); !bytes.Equal(data, tax) {
		t.Fatal("tax content mismatch")
	}
}

func TestCyclicChainIsBounded(t *testing.T) {
	b := fatimg.New(fatimg.FAT16)
	cl, _ := b.AddFile(b.Root(), "loop.bin", "LOOP.BIN", payload(3*b.ClusterSize(), 8), false)
	b.SetFAT(cl[2], cl[0]) // last cluster points back to the first
	// Claim a 4 GiB size so an unbounded walker would spin for millions of steps.
	v := open(t, b)
	var loop Entry
	for _, en := range collect(t, v, false) {
		if en.Name == "loop.bin" {
			loop = en
		}
	}
	loop.Size = 1<<32 - 1
	p := v.PlanFile(loop)
	if p.Confidence == ConfHigh || len(p.Notes) == 0 || p.Extents.Total() != int64(3*b.ClusterSize()) {
		t.Fatalf("cyclic chain not detected: conf=%s notes=%v bytes=%d", p.Confidence, p.Notes, p.Extents.Total())
	}
}

func TestBackupBootSector(t *testing.T) {
	b := fatimg.New(fatimg.FAT32)
	clear(b.B[:512])
	if v := open(t, b); len(v.Warnings) == 0 {
		t.Fatal("use of backup boot sector not reported")
	}
}

func TestCP437Table(t *testing.T) {
	if len(cp437Runes) != 128 {
		t.Fatalf("cp437 table has %d runes", len(cp437Runes))
	}
	if got := decodeOEM("CAF\x82"); got != "CAFé" {
		t.Fatalf("decodeOEM = %q", got)
	}
}

func FuzzParseBootSector(f *testing.F) {
	f.Add(fatimg.New(fatimg.FAT16).B[:512])
	f.Add(fatimg.New(fatimg.FAT32).B[:512])
	f.Fuzz(func(t *testing.T, b []byte) {
		bs, err := ParseBootSector(b)
		if err != nil {
			return
		}
		if bs.ClusterSize() <= 0 || bs.FirstDataSector >= bs.TotalSectors {
			t.Fatalf("accepted inconsistent geometry: %+v", bs)
		}
	})
}

func FuzzWalk(f *testing.F) {
	b := fatimg.New(fatimg.FAT12)
	b.AddFile(b.Root(), "a long file name.txt", "ALONGF~1.TXT", []byte("x"), false)
	f.Add(b.B[:16384])
	f.Fuzz(func(t *testing.T, img []byte) {
		v, err := Open(bytes.NewReader(img), int64(len(img)))
		if err != nil {
			return
		}
		_ = v.Walk(context.Background(), WalkOptions{Deep: true}, func(e Entry) error {
			_ = v.PlanFile(e)
			return nil
		})
	})
}
