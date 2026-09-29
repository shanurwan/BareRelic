package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/shanurwan/barerelic/internal/buildinfo"
	"github.com/shanurwan/barerelic/internal/evidence"
	"github.com/shanurwan/barerelic/internal/extent"
	"github.com/shanurwan/barerelic/internal/rescuemap"
	"github.com/shanurwan/barerelic/internal/source"
)

func (a *app) openSource(path string) (source.Source, error) {
	src, err := source.Open(path)
	if err != nil {
		return nil, err
	}
	a.log.Info("source opened read-only", "path", path, "size", src.Size(), "sector", src.SectorSize(), "device", src.IsDevice())
	return src, nil
}

// checkOutputSeparate refuses to write output onto the evidence itself.
func checkOutputSeparate(src source.Source, out string) error {
	si, err := os.Stat(src.Path())
	if err != nil {
		return nil // devices may not stat on every platform; nothing to compare
	}
	for p := out; ; {
		if oi, err := os.Stat(p); err == nil && os.SameFile(si, oi) {
			return fmt.Errorf("output %q is the source itself; refusing to write to evidence", out)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return nil
		}
		p = parent
	}
}

// loadMap loads an optional rescue map and checks it describes this source.
func loadMap(path string, src source.Source) (*rescuemap.Map, error) {
	if path == "" {
		return nil, nil
	}
	m, err := rescuemap.Load(path)
	if err != nil {
		return nil, fmt.Errorf("load rescue map: %w", err)
	}
	if m.Size() != src.Size() {
		return nil, fmt.Errorf("rescue map covers %d bytes but the source has %d", m.Size(), src.Size())
	}
	return m, nil
}

// unreadable counts bytes of the extents that the rescue map says were never
// read from the original media (they are zero-filled in the image).
func unreadable(m *rescuemap.Map, l extent.List) int64 {
	if m == nil {
		return 0
	}
	var n int64
	for _, e := range l.Physical() {
		n += m.Unrescued(e.Offset, e.Length)
	}
	return n
}

// annotate applies rescue-map knowledge to an artifact.
func annotate(a *evidence.Artifact, m *rescuemap.Map) {
	if u := unreadable(m, a.Extents); u > 0 {
		a.Unreadable = u
		a.Confidence = evidence.Low
		a.Notes = append(a.Notes, fmt.Sprintf("%d bytes lie in regions the imager could not read; they are zero-filled", u))
	}
}

func (a *app) header(op string, c *common, src source.Source, mapPath string, opts any) evidence.Header {
	return evidence.Header{
		Operation: op,
		CaseID:    c.caseID,
		Examiner:  c.examiner,
		Command:   a.args,
		Source: evidence.SourceInfo{
			Path: src.Path(), Size: src.Size(), SectorSize: src.SectorSize(), IsDevice: src.IsDevice(), MapFile: mapPath,
		},
		Tool:    buildinfo.Get(),
		Options: opts,
	}
}

func outcome(partial bool) (string, int) {
	if partial {
		return "partial", ExitPartial
	}
	return "complete", ExitOK
}
