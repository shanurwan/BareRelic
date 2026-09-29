package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/shanurwan/barerelic/internal/buildinfo"
	"github.com/shanurwan/barerelic/internal/evidence"
	"github.com/shanurwan/barerelic/internal/imager"
	"github.com/shanurwan/barerelic/internal/rescuemap"
)

// acquisition is the sidecar record (<image>.barerelic.json) describing how
// an image was produced, across every resumed session.
type acquisition struct {
	Tool        buildinfo.Info      `json:"tool"`
	CaseID      string              `json:"case_id,omitempty"`
	Examiner    string              `json:"examiner,omitempty"`
	Source      evidence.SourceInfo `json:"source"`
	Image       string              `json:"image"`
	Map         string              `json:"map"`
	Sessions    []session           `json:"sessions"`
	Result      imager.Result       `json:"result"`
	ImageSHA256 string              `json:"image_sha256,omitempty"`
	HashNote    string              `json:"hash_note,omitempty"`
}

type session struct {
	Started       time.Time `json:"started"`
	Finished      time.Time `json:"finished"`
	Command       []string  `json:"command"`
	Outcome       string    `json:"outcome"`
	RescuedBefore int64     `json:"rescued_before"`
	RescuedAfter  int64     `json:"rescued_after"`
	ReadErrors    int64     `json:"read_errors"`
	Error         string    `json:"error,omitempty"`
}

func runImage(a *app, args []string) int {
	fs := flag.NewFlagSet("image", flag.ContinueOnError)
	var c common
	c.register(fs)
	out := fs.String("out", "", "destination image file (required)")
	mapPath := fs.String("map", "", "rescue map path (default <out>.map); an existing map resumes the rescue")
	block := fs.Int64("block-size", 64<<10, "copy-phase read size in bytes (multiple of the sector size)")
	retries := fs.Int("retries", 1, "retry passes over bad sectors after scraping")
	skipMax := fs.Int64("skip-max", 0, "largest jump past a read error in the first pass (default 1% of the source, max 1 GiB)")
	noTrim := fs.Bool("no-trim", false, "stop after the copy passes (fastest; leaves failed blocks unexplored)")
	noScrape := fs.Bool("no-scrape", false, "stop after trimming")
	noHash := fs.Bool("no-hash", false, "do not SHA-256 the image when the run ends")
	pos, ok := a.parse(fs, &c, args, "<source>")
	if !ok {
		return ExitUsage
	}
	if len(pos) != 1 || *out == "" {
		return a.usageErr(fs, "exactly one source and --out are required")
	}
	src, err := a.openSource(pos[0])
	if err != nil {
		return a.fail(err)
	}
	defer src.Close()
	if err := checkOutputSeparate(src, *out); err != nil {
		return a.fail(err)
	}
	if *mapPath == "" {
		*mapPath = *out + ".map"
	}
	sidecar := *out + ".barerelic.json"

	var m *rescuemap.Map
	switch mapExists, imgExists := exists(*mapPath), exists(*out); {
	case mapExists && !imgExists:
		return a.fail(fmt.Errorf("map %s exists but image %s does not; refusing to start a fresh image against an old map", *mapPath, *out))
	case mapExists:
		if m, err = rescuemap.Load(*mapPath); err != nil {
			return a.fail(err)
		}
		if m.Size() != src.Size() {
			return a.fail(fmt.Errorf("map %s describes %d bytes but the source has %d: wrong source or wrong map", *mapPath, m.Size(), src.Size()))
		}
		a.log.Info("resuming rescue", "map", *mapPath, "rescued", m.Totals()[rescuemap.Finished])
	case imgExists:
		return a.fail(fmt.Errorf("image %s exists without a map; refusing to overwrite or mix acquisitions", *out))
	default:
		m = rescuemap.New(src.Size())
	}

	dst, err := os.OpenFile(*out, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return a.fail(err)
	}
	defer dst.Close()
	if st, err := dst.Stat(); err != nil {
		return a.fail(err)
	} else if st.Size() > src.Size() {
		return a.fail(fmt.Errorf("image %s is larger than the source", *out))
	} else if st.Size() < src.Size() {
		if err := dst.Truncate(src.Size()); err != nil { // sparse where supported
			return a.fail(fmt.Errorf("pre-size image: %w", err))
		}
	}

	rec := acquisition{}
	if b, err := os.ReadFile(sidecar); err == nil {
		if err := json.Unmarshal(b, &rec); err != nil {
			return a.fail(fmt.Errorf("existing acquisition record %s is unreadable: %w", sidecar, err))
		}
	}
	rec.Tool, rec.Image, rec.Map = buildinfo.Get(), *out, *mapPath
	rec.CaseID, rec.Examiner = firstNonEmpty(c.caseID, rec.CaseID), firstNonEmpty(c.examiner, rec.Examiner)
	rec.Source = evidence.SourceInfo{Path: src.Path(), Size: src.Size(), SectorSize: src.SectorSize(), IsDevice: src.IsDevice()}
	ses := session{Started: time.Now().UTC(), Command: a.args, RescuedBefore: m.Totals()[rescuemap.Finished]}

	res, runErr := imager.Run(a.ctx, src, dst, m, imager.Options{
		BlockSize: *block, Retries: *retries, SkipMax: *skipMax, NoTrim: *noTrim, NoScrape: *noScrape,
		Logger: a.log, Save: func(m *rescuemap.Map) error { return m.Save(*mapPath) },
	})
	ses.Finished, ses.RescuedAfter, ses.ReadErrors = time.Now().UTC(), res.Rescued, res.ReadErrors
	rec.Result = res
	switch {
	case errors.Is(runErr, context.Canceled):
		ses.Outcome = "interrupted"
	case runErr != nil:
		ses.Outcome, ses.Error = "failed", runErr.Error()
	case res.Complete():
		ses.Outcome = "complete"
	default:
		ses.Outcome = "partial"
	}
	rec.Sessions = append(rec.Sessions, ses)

	if runErr == nil && !*noHash {
		sum, err := a.hashFile(dst, src.Size())
		if err != nil {
			return a.fail(fmt.Errorf("hash image: %w", err))
		}
		rec.ImageSHA256 = sum
		rec.HashNote = "SHA-256 of the image file as written"
		if !res.Complete() {
			rec.HashNote += "; unreadable regions are zero-filled — see the map for their locations"
		}
	}
	if err := evidence.WriteJSONAtomic(sidecar, rec); err != nil {
		a.log.Error("write acquisition record", "err", err)
	}

	fmt.Fprintf(a.stdout, "image:      %s\nmap:        %s\nrecord:     %s\n", *out, *mapPath, sidecar)
	fmt.Fprintf(a.stdout, "rescued:    %d / %d bytes (%.4f%%)\nbad:        %d bytes\npending:    %d bytes\nread errors: %d\n",
		res.Rescued, res.Size, 100*float64(res.Rescued)/float64(max(res.Size, 1)), res.BadSector, res.Pending, res.ReadErrors)
	if rec.ImageSHA256 != "" {
		fmt.Fprintf(a.stdout, "sha256:     %s\n", rec.ImageSHA256)
	}
	if runErr != nil {
		return a.fail(runErr)
	}
	if !res.Complete() {
		a.log.Warn("image incomplete; re-run the same command to retry, or continue with analysis of the partial image", "bad_bytes", res.BadSector, "pending_bytes", res.Pending)
		return ExitPartial
	}
	return ExitOK
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func (a *app) hashFile(r io.ReaderAt, size int64) (string, error) {
	h := sha256.New()
	p := newProgress(a, "hashing", size)
	buf := make([]byte, 4<<20)
	for off := int64(0); off < size; {
		if err := a.ctx.Err(); err != nil {
			return "", err
		}
		n, err := r.ReadAt(buf[:min(int64(len(buf)), size-off)], off)
		h.Write(buf[:n])
		off += int64(n)
		if err != nil && !(errors.Is(err, io.EOF) && off == size) {
			return "", err
		}
		p.update(off)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
