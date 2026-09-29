// Package imager acquires a forensic image from failing media using the same
// multi-phase strategy as GNU ddrescue:
//
//  1. copy (skipping):   read large blocks, jump exponentially past errors so
//     healthy areas are secured before the drive degrades further;
//  2. copy (no skip):    read the areas skipped in phase 1;
//  3. trim:              read failed blocks sector-by-sector inward from both
//     edges until the first failure on each side;
//  4. scrape:            read every remaining sector inside failed blocks;
//  5. retry:             re-read bad sectors a bounded number of times.
//
// Progress lives in a rescuemap.Map. The destination is fsynced before every
// map checkpoint, so the map never claims data that is not durably on disk,
// and an interrupted run resumes exactly where it stopped.
package imager

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/shanurwan/barerelic/internal/rescuemap"
)

// Reader is the source being rescued.
type Reader interface {
	io.ReaderAt
	Size() int64
	SectorSize() int
}

// Writer is the destination image.
type Writer interface {
	io.WriterAt
	Sync() error
}

// Options tune the rescue.
type Options struct {
	BlockSize        int64         // copy-phase read size; multiple of the sector size
	SkipMin, SkipMax int64         // exponential skip after a copy-phase error
	Retries          int           // retry passes over bad sectors
	NoTrim           bool          // stop after the copy phases
	NoScrape         bool          // stop after trimming
	SaveInterval     time.Duration // maximum time between map checkpoints
	ProgressInterval time.Duration
	Logger           *slog.Logger
	// Save persists the map. It is called only after the destination has been synced.
	Save func(*rescuemap.Map) error
}

func (o *Options) normalize(sector int64, size int64) error {
	if o.BlockSize == 0 {
		o.BlockSize = 64 << 10
	}
	if o.BlockSize < sector || o.BlockSize%sector != 0 {
		return fmt.Errorf("block size %d must be a positive multiple of the sector size %d", o.BlockSize, sector)
	}
	if o.SkipMin == 0 {
		o.SkipMin = 64 << 10
	}
	if o.SkipMax == 0 {
		o.SkipMax = max(o.SkipMin, min(size/100, 1<<30))
	}
	o.SkipMin = roundUp(o.SkipMin, sector)
	o.SkipMax = roundUp(max(o.SkipMax, o.SkipMin), sector)
	if o.SaveInterval == 0 {
		o.SaveInterval = 30 * time.Second
	}
	if o.ProgressInterval == 0 {
		o.ProgressInterval = 10 * time.Second
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.Save == nil {
		o.Save = func(*rescuemap.Map) error { return nil }
	}
	return nil
}

func roundUp(v, to int64) int64 {
	if r := v % to; r != 0 {
		return v + to - r
	}
	return v
}

// Result summarises the state of the map when Run returned.
type Result struct {
	Size       int64 `json:"size"`
	Rescued    int64 `json:"rescued"`
	BadSector  int64 `json:"bad_sector"`
	Pending    int64 `json:"pending"` // non-tried + non-trimmed + non-scraped
	ReadErrors int64 `json:"read_errors"`
}

// Complete reports whether every byte was rescued.
func (r Result) Complete() bool { return r.Rescued == r.Size }

// ErrDestination wraps failures writing or syncing the destination. These are
// never retried: continuing would silently lose rescued data.
var ErrDestination = errors.New("destination failure")

type run struct {
	ctx        context.Context
	src        Reader
	dst        Writer
	m          *rescuemap.Map
	opt        Options
	sector     int64
	buf        []byte
	readErrors int64
	lastSave   time.Time
	lastLog    time.Time
	started    time.Time
	startBytes int64
}

// Run rescues src into dst according to m, mutating m as it goes. The map
// must cover exactly src.Size() bytes. On context cancellation the map is
// checkpointed and ctx.Err() is returned.
func Run(ctx context.Context, src Reader, dst Writer, m *rescuemap.Map, opt Options) (Result, error) {
	sector := int64(src.SectorSize())
	if sector <= 0 {
		sector = 512
	}
	if m.Size() != src.Size() {
		return Result{}, fmt.Errorf("map covers %d bytes but source has %d; refusing to mix acquisitions", m.Size(), src.Size())
	}
	if err := opt.normalize(sector, src.Size()); err != nil {
		return Result{}, err
	}
	r := &run{
		ctx: ctx, src: src, dst: dst, m: m, opt: opt, sector: sector,
		buf:     make([]byte, opt.BlockSize),
		started: time.Now(),
	}
	r.lastSave, r.lastLog = r.started, r.started
	r.startBytes = m.Totals()[rescuemap.Finished]

	err := r.phases()
	if cerr := r.checkpoint(); err == nil {
		err = cerr
	}
	return r.result(), err
}

func (r *run) phases() error {
	o := r.opt
	r.m.CurrentPhase = rescuemap.PhaseCopying
	r.m.CurrentPass = 1
	if err := r.copyPass(true); err != nil {
		return err
	}
	r.m.CurrentPass = 2
	if err := r.copyPass(false); err != nil {
		return err
	}
	if o.NoTrim {
		return nil
	}
	r.m.CurrentPhase, r.m.CurrentPass = rescuemap.PhaseTrimming, 1
	if err := r.trim(); err != nil {
		return err
	}
	if o.NoScrape {
		return nil
	}
	r.m.CurrentPhase = rescuemap.PhaseScraping
	if err := r.sectorPass(rescuemap.NonScraped); err != nil {
		return err
	}
	r.m.CurrentPhase = rescuemap.PhaseRetrying
	for pass := 1; pass <= o.Retries; pass++ {
		if len(r.m.Regions(rescuemap.BadSector)) == 0 {
			break
		}
		r.m.CurrentPass = pass
		if err := r.sectorPass(rescuemap.BadSector); err != nil {
			return err
		}
	}
	if r.m.Totals()[rescuemap.Finished] == r.m.Size() {
		r.m.CurrentPhase = rescuemap.PhaseFinished
	}
	return nil
}

// read reads [pos,pos+n) and writes whatever was rescued. It returns the
// number of leading bytes rescued (sector-aligned on failure) and the read
// error, if any.
func (r *run) read(pos, n int64) (int64, error) {
	buf := r.buf[:n]
	k, err := r.src.ReadAt(buf, pos)
	if int64(k) == n {
		err = nil
	}
	good := int64(k)
	if err != nil {
		good -= good % r.sector
		r.readErrors++
	}
	if good > 0 {
		if _, werr := r.dst.WriteAt(buf[:good], pos); werr != nil {
			return 0, fmt.Errorf("%w: write at 0x%X: %v", ErrDestination, pos, werr)
		}
	}
	r.m.CurrentPos = pos
	return good, err
}

func (r *run) copyPass(skipping bool) error {
	for _, reg := range r.m.Regions(rescuemap.NonTried) {
		pos, end := reg.Pos, reg.End()
		skip := r.opt.SkipMin
		for pos < end {
			if err := r.tick(); err != nil {
				return err
			}
			n := min(r.opt.BlockSize, end-pos)
			good, err := r.read(pos, n)
			if errors.Is(err, ErrDestination) {
				return err
			}
			if good > 0 {
				r.m.Set(pos, good, rescuemap.Finished)
			}
			if err == nil {
				pos += n
				skip = r.opt.SkipMin
				continue
			}
			r.m.Set(pos+good, n-good, rescuemap.NonTrimmed)
			r.opt.Logger.Debug("read error", "phase", "copy", "pos", pos+good, "err", err)
			pos += n
			if skipping {
				pos += skip // the skipped area stays non-tried for the next pass
				skip = min(skip*2, r.opt.SkipMax)
			}
		}
	}
	return nil
}

// sectorSpan returns the length of the sector-granular read that ends at e
// (handles a final partial sector at the end of the device).
func (r *run) sectorSpan(e, floor int64) int64 {
	n := e % r.sector
	if n == 0 {
		n = r.sector
	}
	return min(n, e-floor)
}

func (r *run) trim() error {
	for _, reg := range r.m.Regions(rescuemap.NonTrimmed) {
		pos, end := reg.Pos, reg.End()
		for pos < end { // leading edge
			if err := r.tick(); err != nil {
				return err
			}
			n := min(r.sector-pos%r.sector, end-pos)
			good, err := r.read(pos, n)
			if errors.Is(err, ErrDestination) {
				return err
			}
			if err == nil {
				r.m.Set(pos, n, rescuemap.Finished)
				pos += n
				continue
			}
			r.m.Set(pos+good, n-good, rescuemap.BadSector)
			pos += n
			break
		}
		for end > pos { // trailing edge
			if err := r.tick(); err != nil {
				return err
			}
			n := r.sectorSpan(end, pos)
			good, err := r.read(end-n, n)
			if errors.Is(err, ErrDestination) {
				return err
			}
			if err == nil {
				r.m.Set(end-n, n, rescuemap.Finished)
				end -= n
				continue
			}
			r.m.Set(end-n+good, n-good, rescuemap.BadSector)
			end -= n
			break
		}
		if end > pos {
			r.m.Set(pos, end-pos, rescuemap.NonScraped)
		}
	}
	return nil
}

// sectorPass reads every sector of every region with status st.
func (r *run) sectorPass(st rescuemap.Status) error {
	for _, reg := range r.m.Regions(st) {
		pos, end := reg.Pos, reg.End()
		for pos < end {
			if err := r.tick(); err != nil {
				return err
			}
			n := min(r.sector-pos%r.sector, end-pos)
			good, err := r.read(pos, n)
			if errors.Is(err, ErrDestination) {
				return err
			}
			if err == nil {
				r.m.Set(pos, n, rescuemap.Finished)
			} else {
				r.m.Set(pos+good, n-good, rescuemap.BadSector)
			}
			pos += n
		}
	}
	return nil
}

// tick handles cancellation, periodic checkpoints and progress logging.
func (r *run) tick() error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	now := time.Now()
	if now.Sub(r.lastSave) >= r.opt.SaveInterval {
		if err := r.checkpoint(); err != nil {
			return err
		}
	}
	if now.Sub(r.lastLog) >= r.opt.ProgressInterval {
		r.lastLog = now
		res := r.result()
		elapsed := now.Sub(r.started).Seconds()
		rate := float64(res.Rescued-r.startBytes) / max(elapsed, 1e-9)
		r.opt.Logger.Info("progress",
			"phase", string(rune(r.m.CurrentPhase)), "pass", r.m.CurrentPass,
			"pos", r.m.CurrentPos, "rescued", res.Rescued, "size", res.Size,
			"pct", fmt.Sprintf("%.2f", 100*float64(res.Rescued)/float64(max(res.Size, 1))),
			"bad", res.BadSector, "pending", res.Pending, "read_errors", res.ReadErrors,
			"rate_bps", int64(rate))
	}
	return nil
}

// checkpoint makes rescued data durable, then persists the map.
func (r *run) checkpoint() error {
	r.lastSave = time.Now()
	if err := r.dst.Sync(); err != nil {
		return fmt.Errorf("%w: sync: %v", ErrDestination, err)
	}
	if err := r.opt.Save(r.m); err != nil {
		return fmt.Errorf("save map: %w", err)
	}
	return nil
}

func (r *run) result() Result {
	t := r.m.Totals()
	return Result{
		Size:       r.m.Size(),
		Rescued:    t[rescuemap.Finished],
		BadSector:  t[rescuemap.BadSector],
		Pending:    t[rescuemap.NonTried] + t[rescuemap.NonTrimmed] + t[rescuemap.NonScraped],
		ReadErrors: r.readErrors,
	}
}
