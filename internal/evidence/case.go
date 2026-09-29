// Package evidence writes recovery output as a self-describing, tamper-evident
// case directory:
//
//	<case>/
//	  journal.jsonl   append-only, fsynced, SHA-256 hash-chained event log
//	  manifest.json   final summary, including the journal head hash
//	  files/...       recovered artifacts (never overwritten, O_EXCL)
//
// Every recovered artifact is hashed while it is written and journaled with
// its source extents, recovery method, confidence and notes, so any claim
// about a recovered file can be traced back to exact bytes on the source.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shanurwan/barerelic/internal/buildinfo"
	"github.com/shanurwan/barerelic/internal/extent"
)

const (
	JournalFile  = "journal.jsonl"
	ManifestFile = "manifest.json"
	FilesDir     = "files"
)

// Confidence levels for recovered artifacts.
const (
	High   = "high"   // structure fully validated / allocation state consistent
	Medium = "medium" // plausible but some assumption was required
	Low    = "low"    // content likely partially overwritten or unverifiable
)

// Extent is a byte range on the original source.
type Extent = extent.Extent

// Artifact describes one recovered file.
type Artifact struct {
	Path         string      `json:"path"` // relative to the case directory, slash-separated
	Size         int64       `json:"size"`
	SHA256       string      `json:"sha256"`
	Method       string      `json:"method"`
	State        string      `json:"state"` // deleted, allocated, orphan, carved
	Confidence   string      `json:"confidence"`
	Type         string      `json:"type,omitempty"`
	OriginalPath string      `json:"original_path,omitempty"`
	Extents      extent.List `json:"extents,omitempty"`
	Modified     *time.Time  `json:"modified,omitempty"`
	Unreadable   int64       `json:"unreadable_bytes,omitempty"` // bytes over unrescued regions of the image
	Notes        []string    `json:"notes,omitempty"`
}

// SourceInfo identifies the evidence a case was derived from.
type SourceInfo struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	SectorSize int    `json:"sector_size"`
	IsDevice   bool   `json:"is_device"`
	MapFile    string `json:"map_file,omitempty"`
}

// Header is journaled when a case is opened.
type Header struct {
	Operation string         `json:"operation"`
	CaseID    string         `json:"case_id,omitempty"`
	Examiner  string         `json:"examiner,omitempty"`
	Command   []string       `json:"command"`
	Source    SourceInfo     `json:"source"`
	Tool      buildinfo.Info `json:"tool"`
	Hostname  string         `json:"hostname,omitempty"`
	Options   any            `json:"options,omitempty"`
}

// Manifest is written when a case is closed.
type Manifest struct {
	Header
	Started    time.Time      `json:"started"`
	Finished   time.Time      `json:"finished"`
	Outcome    string         `json:"outcome"` // complete, partial, interrupted, failed
	Artifacts  int            `json:"artifacts"`
	Bytes      int64          `json:"bytes"`
	Summary    any            `json:"summary,omitempty"`
	Journal    JournalSummary `json:"journal"`
	Warnings   []string       `json:"warnings,omitempty"`
	Confidence map[string]int `json:"confidence"`
}

// JournalSummary pins the journal state that the manifest describes.
type JournalSummary struct {
	File       string `json:"file"`
	Entries    uint64 `json:"entries"`
	HeadSHA256 string `json:"head_sha256"`
}

// Case is an open case directory.
type Case struct {
	dir        string
	header     Header
	started    time.Time
	journal    *Journal
	artifacts  int
	bytes      int64
	warnings   []string
	confidence map[string]int
}

// ErrNotEmpty is returned when the case directory already contains data.
var ErrNotEmpty = errors.New("case directory exists and is not empty")

// Create opens a new case in dir, which must not exist or be empty. Mixing
// the output of two runs in one directory would make provenance ambiguous.
func Create(dir string, h Header) (*Case, error) {
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrNotEmpty, dir)
	}
	if err := os.MkdirAll(filepath.Join(dir, FilesDir), 0o755); err != nil {
		return nil, err
	}
	j, err := createJournal(filepath.Join(dir, JournalFile))
	if err != nil {
		return nil, err
	}
	if h.Tool.Name == "" {
		h.Tool = buildinfo.Get()
	}
	if h.Hostname == "" {
		h.Hostname, _ = os.Hostname()
	}
	c := &Case{dir: dir, header: h, started: time.Now().UTC(), journal: j, confidence: map[string]int{}}
	if err := j.Append("case-opened", h); err != nil {
		j.Close()
		return nil, err
	}
	return c, nil
}

// Dir returns the case directory.
func (c *Case) Dir() string { return c.dir }

// Event journals an arbitrary structured event.
func (c *Case) Event(kind string, data any) error { return c.journal.Append(kind, data) }

// Warn records a warning in both the journal and the manifest.
func (c *Case) Warn(msg string) error {
	c.warnings = append(c.warnings, msg)
	return c.journal.Append("warning", map[string]string{"message": msg})
}

// AddFile writes an artifact to files/<rel>, hashing it on the way. rel is
// untrusted (it usually comes from a directory entry on the evidence) and is
// sanitised. An existing file is never overwritten; a numeric suffix is added.
func (c *Case) AddFile(rel string, content io.Reader, a Artifact) (Artifact, error) {
	rel = path.Join(FilesDir, SanitizePath(rel))
	f, final, err := c.createUnique(rel)
	if err != nil {
		return a, err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), content)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
		// Keep the partial file for examination but journal the failure.
		a.Path, a.Size = final, n
		a.Notes = append(a.Notes, "extraction failed: "+err.Error())
		_ = c.journal.Append("artifact-failed", a)
		return a, fmt.Errorf("write %s: %w", final, err)
	}
	if a.Modified != nil && !a.Modified.IsZero() {
		_ = os.Chtimes(filepath.Join(c.dir, filepath.FromSlash(final)), *a.Modified, *a.Modified)
	}
	a.Path, a.Size, a.SHA256 = final, n, hex.EncodeToString(h.Sum(nil))
	if err := c.journal.Append("artifact", a); err != nil {
		return a, err
	}
	c.artifacts++
	c.bytes += n
	c.confidence[a.Confidence]++
	return a, nil
}

func (c *Case) createUnique(rel string) (*os.File, string, error) {
	dirPart, file := path.Split(rel)
	if err := os.MkdirAll(filepath.Join(c.dir, filepath.FromSlash(dirPart)), 0o755); err != nil {
		return nil, "", err
	}
	ext := path.Ext(file)
	stem := strings.TrimSuffix(file, ext)
	for i := 1; i < 100000; i++ {
		name := file
		if i > 1 {
			name = stem + "~" + strconv.Itoa(i) + ext
		}
		candidate := dirPart + name
		f, err := os.OpenFile(filepath.Join(c.dir, filepath.FromSlash(candidate)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			return f, candidate, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("too many name collisions for %s", rel)
}

// Close journals the outcome and writes manifest.json atomically.
func (c *Case) Close(outcome string, summary any) (*Manifest, error) {
	if err := c.journal.Append("case-closed", map[string]any{"outcome": outcome, "artifacts": c.artifacts, "bytes": c.bytes}); err != nil {
		c.journal.Close()
		return nil, err
	}
	m := &Manifest{
		Header:     c.header,
		Started:    c.started,
		Finished:   time.Now().UTC(),
		Outcome:    outcome,
		Artifacts:  c.artifacts,
		Bytes:      c.bytes,
		Summary:    summary,
		Warnings:   c.warnings,
		Confidence: c.confidence,
		Journal:    JournalSummary{File: JournalFile, Entries: c.journal.Len(), HeadSHA256: c.journal.Head()},
	}
	if err := c.journal.Close(); err != nil {
		return nil, err
	}
	return m, WriteJSONAtomic(filepath.Join(c.dir, ManifestFile), m)
}

// WriteJSONAtomic writes v as indented JSON via temp file, fsync and rename.
func WriteJSONAtomic(dst string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}
