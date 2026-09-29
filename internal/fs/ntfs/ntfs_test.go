package ntfs

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"strings"
	"testing"

	img "github.com/shanurwan/barerelic/internal/testutil/ntfsimg"
)

func payload(n int, seed int64) []byte {
	p := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(p)
	return p
}

type scenario struct {
	img                                 []byte
	report, cat, old, secret, adsMain   []byte
	adsZone, listed, sparseHead, orphan []byte
}

func buildScenario() *scenario {
	s := &scenario{
		report:     []byte("quarterly numbers: 42\n"),
		cat:        payload(2*img.CS+1234, 1),
		old:        payload(img.CS, 2),
		secret:     payload(3000, 3),
		adsMain:    []byte("downloaded installer"),
		adsZone:    []byte("[ZoneTransfer]\r\nZoneId=3\r\n"),
		listed:     payload(img.CS+10, 4),
		sparseHead: payload(img.CS, 5),
		orphan:     []byte("orphaned but intact"),
	}
	im := img.New()

	// 30: live resident file.
	im.Put(img.Rec{Num: 30, Seq: 1, Flags: img.FlagInUse, Attrs: [][]byte{
		img.StdInfo(img.Time), img.FileName(img.Root, "report.txt", img.NSWin32), img.Resident(img.AttrData, "", s.report)}})

	// 31: live directory "Photos"; 32: deleted, fragmented file inside it
	// with both a DOS alias and a Win32 name.
	im.Put(img.Rec{Num: 31, Seq: 2, Flags: img.FlagInUse | img.FlagDirectory, Attrs: [][]byte{img.FileName(img.Root, "Photos", img.NSWin32)}})
	im.Write(100, s.cat[:2*img.CS])
	im.Write(200, s.cat[2*img.CS:])
	im.Put(img.Rec{Num: 32, Seq: 4, Attrs: [][]byte{
		img.StdInfo(img.Time), img.FileName(img.Ref(31, 2), "CAT~1.JPG", img.NSDOS), img.FileName(img.Ref(31, 2), "cat on the sofa.jpg", img.NSWin32),
		img.Data(int64(len(s.cat)), img.Run{LCN: 100, N: 2}, img.Run{LCN: 200, N: 1})}})

	// 33: deleted file whose cluster was reallocated.
	im.Write(300, s.old)
	im.Alloc(300)
	im.Put(img.Rec{Num: 33, Seq: 3, Attrs: [][]byte{
		img.FileName(img.Root, "old.bin", img.NSWin32), img.Data(int64(len(s.old)), img.Run{LCN: 300, N: 1})}})

	// 34: deleted directory (sequence bumped to 8 on deletion); 35: deleted
	// file inside it that still references sequence 7.
	im.Put(img.Rec{Num: 34, Seq: 8, Flags: img.FlagDirectory, Attrs: [][]byte{img.FileName(img.Root, "Secret", img.NSWin32)}})
	im.Write(400, s.secret)
	im.Put(img.Rec{Num: 35, Seq: 2, Attrs: [][]byte{
		img.FileName(img.Ref(34, 7), "plans.docx", img.NSWin32), img.Data(int64(len(s.secret)), img.Run{LCN: 400, N: 1})}})

	// 36: live file with an alternate data stream.
	im.Put(img.Rec{Num: 36, Seq: 1, Flags: img.FlagInUse, Attrs: [][]byte{
		img.FileName(img.Root, "setup.exe", img.NSWin32), img.Resident(img.AttrData, "", s.adsMain), img.Resident(img.AttrData, "Zone.Identifier", s.adsZone)}})

	// 37: deleted file whose parent record 40 was reused by something else.
	im.Put(img.Rec{Num: 40, Seq: 9, Flags: img.FlagInUse | img.FlagDirectory, Attrs: [][]byte{img.FileName(img.Root, "NewDir", img.NSWin32)}})
	im.Put(img.Rec{Num: 37, Seq: 2, Attrs: [][]byte{
		img.FileName(img.Ref(40, 3), "lost.txt", img.NSWin32), img.Resident(img.AttrData, "", s.orphan)}})

	// 38 + 39: deleted file whose $DATA lives in an extension record.
	im.Write(500, s.listed)
	im.Put(img.Rec{Num: 38, Seq: 5, Attrs: [][]byte{
		img.AttrList([][3]uint64{{img.AttrFileName, 0, img.Ref(38, 4)}, {img.AttrData, 0, img.Ref(39, 1)}}),
		img.FileName(img.Root, "big-attrlist.dat", img.NSWin32)}})
	im.Put(img.Rec{Num: 39, Seq: 2, Base: img.Ref(38, 4), Attrs: [][]byte{
		img.Data(int64(len(s.listed)), img.Run{LCN: 500, N: 2})}})

	// 41: live sparse file: 1 real cluster, 2 sparse; initialized size stops mid-file.
	im.Write(600, s.sparseHead)
	im.Alloc(600)
	im.Put(img.Rec{Num: 41, Seq: 1, Flags: img.FlagInUse, Attrs: [][]byte{
		img.FileName(img.Root, "sparse.vhd", img.NSWin32),
		img.NonResident(img.AttrData, "", []img.Run{{LCN: 600, N: 1}, {LCN: -1, N: 2}}, 0, 3*img.CS, img.CS-100, img.FlagSparse)}})

	s.img = im.Finish()
	return s
}

func open(t *testing.T, b []byte) *Volume {
	t.Helper()
	v, err := Open(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func walkAll(t *testing.T, v *Volume, opt WalkOptions) map[string]File {
	t.Helper()
	got := map[string]File{}
	if err := v.Walk(context.Background(), opt, func(f File) error {
		got[f.Path] = f
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func content(t *testing.T, v *Volume, f File, stream string) ([]byte, Plan) {
	t.Helper()
	for _, s := range f.Streams {
		if s.Name == stream {
			p := v.PlanStream(f, s)
			if !p.Recoverable {
				t.Fatalf("%s:%s not recoverable: %v", f.Path, stream, p.Notes)
			}
			b, err := io.ReadAll(v.Reader(p))
			if err != nil {
				t.Fatal(err)
			}
			return b, p
		}
	}
	t.Fatalf("%s has no stream %q", f.Path, stream)
	return nil, Plan{}
}

func names(m map[string]File) string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return strings.Join(out, ", ")
}

func TestDeletedFileRecovery(t *testing.T) {
	s := buildScenario()
	v := open(t, s.img)
	if len(v.Warnings) != 0 {
		t.Fatalf("unexpected warnings on a clean volume: %v", v.Warnings)
	}
	got := walkAll(t, v, WalkOptions{Scope: ScopeDeleted})

	cat, ok := got["/Photos/cat on the sofa.jpg"]
	if !ok || !cat.Deleted {
		t.Fatalf("fragmented deleted file not found (Win32 name must beat DOS alias): %s", names(got))
	}
	if b, p := content(t, v, cat, ""); !bytes.Equal(b, s.cat) || p.Confidence != ConfHigh {
		t.Fatalf("cat.jpg content/confidence wrong: %s %v", p.Confidence, p.Notes)
	}
	if !cat.Modified.Equal(img.Time) {
		t.Fatalf("timestamp = %v", cat.Modified)
	}

	if _, p := content(t, v, got["/old.bin"], ""); p.Confidence != ConfLow {
		t.Fatalf("reallocated clusters must lower confidence, got %s", p.Confidence)
	}

	plans, ok := got["/Secret/plans.docx"]
	if !ok {
		t.Fatalf("path through deleted parent (sequence+1 rule) not resolved: %s", names(got))
	}
	if b, _ := content(t, v, plans, ""); !bytes.Equal(b, s.secret) {
		t.Fatal("plans.docx content mismatch")
	}

	lost, ok := got["/$OrphanFiles/lost.txt"]
	if !ok || !lost.Orphan {
		t.Fatalf("file with reused parent must be an orphan: %s", names(got))
	}
	if b, _ := content(t, v, lost, ""); !bytes.Equal(b, s.orphan) {
		t.Fatal("orphan resident content mismatch")
	}

	listed, ok := got["/big-attrlist.dat"]
	if !ok {
		t.Fatalf("attribute-list file missing: %s", names(got))
	}
	if b, _ := content(t, v, listed, ""); !bytes.Equal(b, s.listed) {
		t.Fatal("data from extension record mismatch")
	}

	for p := range got {
		if strings.Contains(p, "report.txt") || strings.Contains(p, "setup.exe") || strings.Contains(p, "$MFT") {
			t.Fatalf("scope=deleted returned live/system file %s", p)
		}
	}
}

func TestAllScopeLiveFilesAndStreams(t *testing.T) {
	s := buildScenario()
	v := open(t, s.img)
	got := walkAll(t, v, WalkOptions{Scope: ScopeAll})
	if b, _ := content(t, v, got["/report.txt"], ""); !bytes.Equal(b, s.report) {
		t.Fatal("resident live content mismatch")
	}
	if b, _ := content(t, v, got["/setup.exe"], "Zone.Identifier"); !bytes.Equal(b, s.adsZone) {
		t.Fatal("alternate data stream mismatch")
	}
	b, _ := content(t, v, got["/sparse.vhd"], "")
	want := append(append([]byte(nil), s.sparseHead[:img.CS-100]...), make([]byte, 2*img.CS+100)...)
	if !bytes.Equal(b, want) {
		t.Fatalf("sparse/uninitialized regions must read as zeros (len %d want %d)", len(b), len(want))
	}
	if _, ok := got["/$MFT"]; ok {
		t.Fatal("system files must be excluded by default")
	}
}

func TestMirrorAndBackupBootFallback(t *testing.T) {
	b := append([]byte(nil), buildScenario().img...)
	clear(b[:512])                                         // destroy primary boot sector
	clear(b[img.MFTLCN*img.CS : img.MFTLCN*img.CS+img.RS]) // destroy $MFT record 0
	v := open(t, b)
	if len(v.Warnings) < 2 {
		t.Fatalf("fallbacks not reported: %v", v.Warnings)
	}
	if _, ok := walkAll(t, v, WalkOptions{})["/Photos/cat on the sofa.jpg"]; !ok {
		t.Fatal("recovery via $MFTMirr failed")
	}
}

func TestTornRecordRejected(t *testing.T) {
	rec := img.Record(img.Rec{Num: 50, Seq: 1, Attrs: [][]byte{img.FileName(img.Root, "x", img.NSWin32)}})
	rec[fixupStride-1] ^= 0xFF
	if _, err := ParseRecord(rec); err == nil {
		t.Fatal("torn record accepted")
	}
}

func TestFormattedVolumeDeepScan(t *testing.T) {
	// Previous file system: records for "wedding.mov" and "note.txt" lived in
	// an old MFT region at cluster 1000. The new MFT knows nothing of them.
	b := append([]byte(nil), buildScenario().img...)
	movie := payload(img.CS+77, 9)
	copy(b[700*img.CS:], movie)
	copy(b[1000*img.CS:], img.Record(img.Rec{Num: 64, Seq: 3, Flags: img.FlagInUse, Attrs: [][]byte{
		img.StdInfo(img.Time), img.FileName(img.Root, "wedding.mov", img.NSWin32),
		img.Data(int64(len(movie)), img.Run{LCN: 700, N: 2})}}))
	copy(b[1000*img.CS+img.RS:], img.Record(img.Rec{Num: 65, Seq: 1, Flags: img.FlagInUse, Attrs: [][]byte{
		img.FileName(img.Root, "note.txt", img.NSWin32), img.Resident(img.AttrData, "", []byte("remember"))}}))

	v := open(t, b)
	for p := range walkAll(t, v, WalkOptions{}) {
		if strings.Contains(p, "wedding") {
			t.Fatal("shallow walk must not see records outside the MFT")
		}
	}
	deep := walkAll(t, v, WalkOptions{Deep: true})
	var mov, note File
	for p, f := range deep {
		if strings.HasSuffix(p, "wedding.mov") {
			mov = f
		}
		if strings.HasSuffix(p, "note.txt") {
			note = f
		}
		if strings.HasPrefix(p, "/$OrphanRecords") && strings.Contains(p, "$MFT") {
			t.Fatal("$MFTMirr records must be skipped")
		}
	}
	if !mov.OutsideMFT || !note.OutsideMFT {
		t.Fatalf("deep scan missed old records: %s", names(deep))
	}
	got, p := content(t, v, mov, "")
	if !bytes.Equal(got, movie) || p.Confidence != ConfMedium {
		t.Fatalf("old-MFT file: equal=%v conf=%s", bytes.Equal(got, movie), p.Confidence)
	}
	if got, _ := content(t, v, note, ""); string(got) != "remember" {
		t.Fatal("old-MFT resident content mismatch")
	}
}

func TestDecodeRuns(t *testing.T) {
	runs := []img.Run{{LCN: 0x1000, N: 16}, {LCN: 0x0800, N: 3}, {LCN: -1, N: 5}, {LCN: 0x123456, N: 1}}
	got, err := DecodeRuns(img.EncodeRuns(runs), 10)
	if err != nil {
		t.Fatal(err)
	}
	vcn := int64(10)
	for i, r := range runs {
		want := Run{VCN: vcn, LCN: r.LCN, Length: r.N}
		if got[i] != want {
			t.Fatalf("run %d = %+v, want %+v", i, got[i], want)
		}
		vcn += r.N
	}
}

func FuzzParseRecord(f *testing.F) {
	f.Add(img.Record(img.Rec{Num: 30, Seq: 1, Flags: img.FlagInUse, Attrs: [][]byte{
		img.FileName(img.Root, "a.txt", img.NSWin32), img.Resident(img.AttrData, "", []byte("x")),
		img.NonResident(img.AttrData, "s", []img.Run{{LCN: 5, N: 1}, {LCN: -1, N: 2}}, 0, 100, 100, 0)}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		rec, err := ParseRecord(b)
		if err != nil || rec == nil {
			return
		}
		for _, a := range rec.Attrs {
			if a.Type == AttrFileName && !a.NonResident {
				_, _ = ParseFileName(a.Value)
			}
		}
	})
}

func FuzzDecodeRuns(f *testing.F) {
	f.Add(img.EncodeRuns([]img.Run{{LCN: 100, N: 3}, {LCN: -1, N: 2}, {LCN: 50, N: 1}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		runs, _ := DecodeRuns(b, 0)
		for _, r := range runs {
			if r.Length <= 0 || (r.LCN < 0 && r.LCN != -1) {
				t.Fatalf("invalid run accepted: %+v", r)
			}
		}
	})
}
