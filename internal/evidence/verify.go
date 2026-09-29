package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Report is the result of verifying a case directory.
type Report struct {
	Entries   int      `json:"entries"`
	Artifacts int      `json:"artifacts"`
	Verified  int      `json:"verified"`
	Problems  []string `json:"problems,omitempty"`
}

// OK reports whether the case verified cleanly.
func (r Report) OK() bool { return len(r.Problems) == 0 }

// Verify re-checks a case directory: the journal hash chain, the manifest's
// pinned journal head, and the SHA-256 of every journaled artifact.
func Verify(dir string) (Report, error) {
	var rep Report
	jf, err := os.Open(filepath.Join(dir, JournalFile))
	if err != nil {
		return rep, err
	}
	entries, head, chainErr := ReadJournal(jf)
	jf.Close()
	rep.Entries = len(entries)
	if chainErr != nil {
		rep.Problems = append(rep.Problems, chainErr.Error())
	}

	mb, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	switch {
	case os.IsNotExist(err):
		rep.Problems = append(rep.Problems, "manifest.json missing (run interrupted before close?)")
	case err != nil:
		return rep, err
	default:
		var m Manifest
		if err := json.Unmarshal(mb, &m); err != nil {
			rep.Problems = append(rep.Problems, "manifest.json unreadable: "+err.Error())
		} else if chainErr == nil && (m.Journal.HeadSHA256 != head || m.Journal.Entries != uint64(len(entries))) {
			rep.Problems = append(rep.Problems, fmt.Sprintf(
				"manifest pins journal %d entries / head %s, journal has %d / %s",
				m.Journal.Entries, m.Journal.HeadSHA256, len(entries), head))
		}
	}

	for _, e := range entries {
		if e.Kind != "artifact" {
			continue
		}
		rep.Artifacts++
		var a Artifact
		if err := json.Unmarshal(e.Data, &a); err != nil {
			rep.Problems = append(rep.Problems, fmt.Sprintf("seq %d: bad artifact record: %v", e.Seq, err))
			continue
		}
		clean := path.Clean(a.Path)
		if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") || !strings.HasPrefix(clean, FilesDir+"/") {
			rep.Problems = append(rep.Problems, fmt.Sprintf("seq %d: artifact path %q escapes the case directory", e.Seq, a.Path))
			continue
		}
		sum, size, err := hashFile(filepath.Join(dir, filepath.FromSlash(clean)))
		switch {
		case err != nil:
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s: %v", a.Path, err))
		case sum != a.SHA256 || size != a.Size:
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s: content changed (sha256 %s size %d, journal says %s size %d)", a.Path, sum, size, a.SHA256, a.Size))
		default:
			rep.Verified++
		}
	}
	return rep, nil
}

func hashFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}
