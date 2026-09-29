package evidence

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeComponent(t *testing.T) {
	cases := map[string]string{
		"report.docx":    "report.docx",
		"..":             "__",
		".":              "_",
		"":               "_",
		"a/b":            "a_b",
		`a\b`:            "a_b",
		"CON":            "_CON",
		"con.txt":        "_con.txt",
		"LPT1.log":       "_LPT1.log",
		"console.txt":    "console.txt",
		"trail. ":        "trail__",
		"x:ads":          "x_ads",
		"bell\x07":       "bell_",
		"\xff\xfeutf":    "_utf",
		"résumé.pdf":     "résumé.pdf",
		"què?*<>|\".txt": "què______.txt",
	}
	for in, want := range cases {
		if got := SanitizeComponent(in); got != want {
			t.Errorf("SanitizeComponent(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("é", 300)
	if got := SanitizeComponent(long); len(got) > maxComponentBytes || !strings.HasPrefix(long, got) {
		t.Errorf("long name not truncated on a rune boundary: %d bytes", len(got))
	}
}

func TestSanitizePathCannotEscape(t *testing.T) {
	for _, in := range []string{"../../etc/passwd", `..\..\Windows\System32`, "/abs/path", "a/../../b", "C:/x"} {
		got := SanitizePath(in)
		if strings.HasPrefix(got, "/") || strings.HasPrefix(got, "..") || strings.Contains(got, "/../") || strings.Contains(got, ":") {
			t.Errorf("SanitizePath(%q) = %q escapes its root", in, got)
		}
	}
}

func newCase(t *testing.T) (*Case, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "case")
	c, err := Create(dir, Header{Operation: "test", Command: []string{"barerelic", "test"}})
	if err != nil {
		t.Fatal(err)
	}
	return c, dir
}

func TestCaseLifecycleAndVerify(t *testing.T) {
	c, dir := newCase(t)
	a, err := c.AddFile("docs/../../evil.txt", strings.NewReader("hello"), Artifact{Method: "test", State: "deleted", Confidence: High})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(a.Path, "files/") || strings.Contains(a.Path, "..") {
		t.Fatalf("artifact escaped files/: %s", a.Path)
	}
	b, err := c.AddFile("docs/../../evil.txt", strings.NewReader("world"), Artifact{Method: "test", Confidence: Low})
	if err != nil {
		t.Fatal(err)
	}
	if b.Path == a.Path || !strings.HasSuffix(b.Path, "evil~2.txt") {
		t.Fatalf("collision not suffixed: %s vs %s", a.Path, b.Path)
	}
	if a.SHA256 != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("sha256 = %s", a.SHA256)
	}
	m, err := c.Close("complete", nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Artifacts != 2 || m.Confidence[High] != 1 || m.Confidence[Low] != 1 {
		t.Fatalf("manifest = %+v", m)
	}
	rep, err := Verify(dir)
	if err != nil || !rep.OK() || rep.Verified != 2 {
		t.Fatalf("verify: %+v %v", rep, err)
	}

	// Tamper with an artifact.
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(a.Path)), []byte("HELLO"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rep, _ := Verify(dir); rep.OK() {
		t.Fatal("modified artifact not detected")
	}
}

func TestJournalTamperDetected(t *testing.T) {
	c, dir := newCase(t)
	c.AddFile("a.bin", bytes.NewReader([]byte{1, 2, 3}), Artifact{Confidence: High})
	c.AddFile("b.bin", bytes.NewReader([]byte{4, 5, 6}), Artifact{Confidence: High})
	c.Close("complete", nil)

	jp := filepath.Join(dir, JournalFile)
	orig, _ := os.ReadFile(jp)
	lines := strings.SplitAfter(string(orig), "\n")

	edited := strings.Replace(string(orig), `"confidence":"high"`, `"confidence":"low"`, 1)
	os.WriteFile(jp, []byte(edited), 0o644)
	if _, _, err := ReadJournal(strings.NewReader(edited)); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("edited entry not detected: %v", err)
	}

	dropped := strings.Join(append(lines[:1:1], lines[2:]...), "")
	if _, _, err := ReadJournal(strings.NewReader(dropped)); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("deleted entry not detected: %v", err)
	}

	// Truncating trailing entries keeps a valid chain; the manifest pin catches it.
	truncated := strings.Join(lines[:len(lines)-2], "")
	os.WriteFile(jp, []byte(truncated), 0o644)
	if rep, _ := Verify(dir); rep.OK() {
		t.Fatal("truncated journal not detected via manifest pin")
	}
}

func TestCreateRefusesNonEmptyDir(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "existing"), nil, 0o644)
	if _, err := Create(dir, Header{}); !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("expected ErrNotEmpty, got %v", err)
	}
}
