package cli

import (
	"flag"
	"fmt"
	"io"
	"path"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/shanurwan/barerelic/internal/evidence"
	"github.com/shanurwan/barerelic/internal/fs/fat"
	"github.com/shanurwan/barerelic/internal/fs/ntfs"
	"github.com/shanurwan/barerelic/internal/fsdetect"
	"github.com/shanurwan/barerelic/internal/rescuemap"
	"github.com/shanurwan/barerelic/internal/volume"
)

type recoverOpts struct {
	All           bool   `json:"all"`
	Deep          bool   `json:"deep"`
	IncludeSystem bool   `json:"include_system"`
	FS            string `json:"fs"`
	Partition     int    `json:"partition"`
	Offset        int64  `json:"offset"`
}

// volumeStats are reported per volume in the manifest summary.
type volumeStats struct {
	Volume     string         `json:"volume"`
	FS         string         `json:"fs"`
	Start      int64          `json:"start"`
	Found      int            `json:"found"`
	Recovered  int            `json:"recovered"`
	Skipped    int            `json:"skipped"`
	Failed     int            `json:"failed"`
	Unreadable int            `json:"with_unreadable_bytes"`
	Bytes      int64          `json:"bytes"`
	Confidence map[string]int `json:"confidence"`
	Error      string         `json:"error,omitempty"`
}

// sink sends recovered files either into a case or, for --dry-run, to a listing.
type sink struct {
	a  *app
	c  *evidence.Case
	tw *tabwriter.Writer
	m  *rescuemap.Map
	vs *volumeStats
}

func (s *sink) warn(msg string) {
	s.a.log.Warn(msg, "volume", s.vs.Volume)
	if s.c != nil {
		_ = s.c.Warn(s.vs.Volume + ": " + msg)
	}
}

func (s *sink) skip(art evidence.Artifact) {
	s.vs.Found++
	s.vs.Skipped++
	if s.tw != nil {
		fmt.Fprintf(s.tw, "%s\t%s\t-\t%s\t%s\n", art.State, "skip", art.OriginalPath, strings.Join(art.Notes, "; "))
		return
	}
	if s.c != nil {
		_ = s.c.Event("artifact-skipped", art)
	}
}

func (s *sink) file(rel string, content io.Reader, art evidence.Artifact) error {
	s.vs.Found++
	annotate(&art, s.m)
	if art.Unreadable > 0 {
		s.vs.Unreadable++
	}
	if s.tw != nil {
		fmt.Fprintf(s.tw, "%s\t%s\t%d\t%s\t%s\n", art.State, art.Confidence, art.Extents.Total(), art.OriginalPath, strings.Join(art.Notes, "; "))
		return nil
	}
	got, err := s.c.AddFile(rel, content, art)
	if err != nil {
		s.vs.Failed++
		s.a.log.Warn("extraction failed", "path", art.OriginalPath, "err", err)
		return nil // keep going: one unreadable file must not stop the recovery
	}
	s.vs.Recovered++
	s.vs.Bytes += got.Size
	s.vs.Confidence[got.Confidence]++
	return nil
}

func runRecover(a *app, args []string) int {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	var c common
	c.register(fs)
	out := fs.String("out", "", "case directory to create (must not exist or be empty)")
	var o recoverOpts
	fs.IntVar(&o.Partition, "partition", -1, "partition number from `probe` (default: every supported volume)")
	fs.Int64Var(&o.Offset, "offset", -1, "byte offset of a volume (e.g. a lost partition from `probe --scan`)")
	size := fs.Int64("size", 0, "volume size in bytes with --offset (default: to the end of the source)")
	fs.StringVar(&o.FS, "fs", "auto", "file system: auto, fat, ntfs")
	fs.BoolVar(&o.All, "all", false, "recover live files too, not only deleted ones")
	fs.BoolVar(&o.Deep, "deep", false, "also scan for orphaned metadata (formatted volumes): FAT directory clusters, NTFS records outside the MFT")
	fs.BoolVar(&o.IncludeSystem, "include-system", false, "include NTFS metafiles ($MFT, $LogFile, $Extend, ...)")
	mapPath := fs.String("map", "", "rescue map of the image; files touching unreadable regions are flagged")
	dry := fs.Bool("dry-run", false, "list what would be recovered without writing anything")
	pos, ok := a.parse(fs, &c, args, "<source>")
	if !ok {
		return ExitUsage
	}
	if len(pos) != 1 || (*out == "" && !*dry) {
		return a.usageErr(fs, "a source and --out (or --dry-run) are required")
	}
	if o.FS != "auto" && o.FS != "fat" && o.FS != "ntfs" {
		return a.usageErr(fs, "--fs must be auto, fat or ntfs")
	}
	src, err := a.openSource(pos[0])
	if err != nil {
		return a.fail(err)
	}
	defer src.Close()
	m, err := loadMap(*mapPath, src)
	if err != nil {
		return a.fail(err)
	}

	var targets []volumeInfo
	if o.Offset >= 0 {
		if o.Offset >= src.Size() {
			return a.usageErr(fs, "--offset beyond the end of the source")
		}
		v := volumeInfo{Partition: volume.Partition{Index: -1, Start: o.Offset, Size: src.Size() - o.Offset}, Source: "--offset"}
		if *size > 0 {
			v.Size = min(*size, v.Size)
		}
		if f, ok := fsdetect.Identify(src, o.Offset); ok {
			v.FS = &f
		}
		targets = append(targets, v)
	} else {
		vols, _, warns := discoverVolumes(src, src.Size(), src.SectorSize())
		for _, w := range warns {
			a.log.Warn(w)
		}
		for _, v := range vols {
			if o.Partition >= 0 && v.Index != o.Partition {
				continue
			}
			targets = append(targets, v)
		}
		if len(targets) == 0 {
			return a.fail(fmt.Errorf("no matching volume; run `barerelic probe` (or `probe --scan`) and pass --partition or --offset"))
		}
	}

	var cs *evidence.Case
	var tw *tabwriter.Writer
	if *dry {
		tw = tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "STATE\tCONFIDENCE\tSIZE\tPATH\tNOTES")
	} else {
		if err := checkOutputSeparate(src, *out); err != nil {
			return a.fail(err)
		}
		if cs, err = evidence.Create(*out, a.header("recover", &c, src, *mapPath, o)); err != nil {
			return a.fail(err)
		}
	}

	var all []*volumeStats
	partial := false
	for _, v := range targets {
		kind := o.FS
		if kind == "auto" {
			switch {
			case v.FS == nil:
				kind = ""
			case v.FS.Type == "ntfs":
				kind = "ntfs"
			case strings.HasPrefix(v.FS.Type, "fat"):
				kind = "fat"
			}
		}
		name := fmt.Sprintf("p%d", v.Index)
		if v.Index < 0 {
			name = fmt.Sprintf("off_%d", v.Start)
		}
		vs := &volumeStats{Volume: name, FS: kind, Start: v.Start, Confidence: map[string]int{}}
		all = append(all, vs)
		if kind == "" {
			reason := "no supported file system"
			if v.FS != nil {
				reason = "file system " + v.FS.Type + " is not supported for metadata recovery; use `carve`"
			}
			vs.Error = reason
			a.log.Info("skipping volume", "volume", name, "reason", reason)
			continue
		}
		volSize := min(v.Size, src.Size()-v.Start)
		sec := io.NewSectionReader(src, v.Start, volSize)
		s := &sink{a: a, c: cs, tw: tw, m: m, vs: vs}
		a.log.Info("recovering", "volume", name, "fs", kind, "start", v.Start, "size", volSize, "deep", o.Deep)
		var err error
		switch kind {
		case "fat":
			err = recoverFAT(a, s, sec, volSize, v.Start, name, o)
		case "ntfs":
			err = recoverNTFS(a, s, sec, volSize, v.Start, name, o)
		}
		if err != nil {
			vs.Error = err.Error()
			if a.ctx.Err() != nil {
				break
			}
			a.log.Error("volume failed", "volume", name, "err", err)
			partial = true
		}
		if vs.Failed > 0 || vs.Unreadable > 0 {
			partial = true
		}
		a.log.Info("volume done", "volume", name, "found", vs.Found, "recovered", vs.Recovered, "skipped", vs.Skipped, "failed", vs.Failed)
	}

	if tw != nil {
		tw.Flush()
		return ExitOK
	}
	result, code := outcome(partial)
	if a.ctx.Err() != nil {
		result, code = "interrupted", ExitInterrupted
	}
	man, err := cs.Close(result, all)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "case:       %s\noutcome:    %s\nartifacts:  %d (%s)\n", *out, man.Outcome, man.Artifacts, humanBytes(man.Bytes))
	for _, k := range []string{evidence.High, evidence.Medium, evidence.Low} {
		fmt.Fprintf(a.stdout, "  %-7s  %d\n", k, man.Confidence[k])
	}
	for _, vs := range all {
		fmt.Fprintf(a.stdout, "volume %-12s fs=%-5s found=%d recovered=%d skipped=%d failed=%d", vs.Volume, vs.FS, vs.Found, vs.Recovered, vs.Skipped, vs.Failed)
		if vs.Error != "" {
			fmt.Fprintf(a.stdout, " (%s)", vs.Error)
		}
		fmt.Fprintln(a.stdout)
	}
	fmt.Fprintf(a.stdout, "journal:    %s (head %s)\n", path.Join(*out, evidence.JournalFile), man.Journal.HeadSHA256)
	return code
}

func state(deleted, orphan bool) string {
	switch {
	case orphan:
		return "orphan"
	case deleted:
		return "deleted"
	}
	return "allocated"
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func recoverFAT(a *app, s *sink, r io.ReaderAt, size, base int64, name string, o recoverOpts) error {
	v, err := fat.Open(r, size)
	if err != nil {
		return err
	}
	for _, w := range v.Warnings {
		s.warn(w)
	}
	nWarn := len(v.Warnings)
	err = v.Walk(a.ctx, fat.WalkOptions{Deep: o.Deep}, func(e fat.Entry) error {
		if e.Dir || (!o.All && !e.Deleted) {
			return nil
		}
		plan := v.PlanFile(e)
		method := "fat-directory-entry"
		if e.Orphan {
			method = "fat-orphan-directory"
		}
		art := evidence.Artifact{
			Method: method, State: state(e.Deleted, e.Orphan), Confidence: plan.Confidence,
			Type: strings.ToLower(v.BS.Type.String()), OriginalPath: e.Path,
			Extents: plan.Extents.Shift(base), Modified: timePtr(e.Modified),
			Notes: append(append([]string{fmt.Sprintf("directory entry at source offset 0x%X; start cluster %d; size %d", base+e.EntryOffset, e.Cluster, e.Size)}, e.Notes...), plan.Notes...),
		}
		if !plan.Recoverable {
			s.skip(art)
			return nil
		}
		return s.file(path.Join(name, e.Path), v.Reader(plan), art)
	})
	for _, w := range v.Warnings[nWarn:] {
		s.warn(w)
	}
	return err
}

func recoverNTFS(a *app, s *sink, r io.ReaderAt, size, base int64, name string, o recoverOpts) error {
	v, err := ntfs.Open(r, size)
	if err != nil {
		return err
	}
	for _, w := range v.Warnings {
		s.warn(w)
	}
	nWarn := len(v.Warnings)
	scope := ntfs.ScopeDeleted
	if o.All {
		scope = ntfs.ScopeAll
	}
	err = v.Walk(a.ctx, ntfs.WalkOptions{Scope: scope, Deep: o.Deep, IncludeSystem: o.IncludeSystem}, func(f ntfs.File) error {
		method := "ntfs-mft"
		if f.OutsideMFT {
			method = "ntfs-orphan-record"
		}
		prov := fmt.Sprintf("MFT record %d (sequence %d) at source offset 0x%X", f.Record, f.Sequence, base+f.RecordOffset)
		if len(f.Streams) == 0 {
			s.skip(evidence.Artifact{Method: method, State: state(f.Deleted, f.OutsideMFT), OriginalPath: f.Path,
				Notes: append([]string{prov, "record has no $DATA attribute left"}, f.Notes...)})
			return nil
		}
		for _, st := range f.Streams {
			plan := v.PlanStream(f, st)
			orig, rel := f.Path, path.Join(name, f.Path)
			if st.Name != "" {
				orig += ":" + st.Name
				rel += "_ADS_" + st.Name
			}
			// For resident data the extent locates the value inside the MFT
			// record (provenance only: fixups mean the raw bytes differ slightly).
			art := evidence.Artifact{
				Method: method, State: state(f.Deleted, f.OutsideMFT), Confidence: plan.Confidence,
				Type: "ntfs", OriginalPath: orig, Extents: plan.Extents.Shift(base), Modified: timePtr(f.Modified),
				Notes: append(append([]string{prov}, f.Notes...), plan.Notes...),
			}
			if !plan.Recoverable {
				s.skip(art)
				continue
			}
			if err := s.file(rel, v.Reader(plan), art); err != nil {
				return err
			}
		}
		return nil
	})
	for _, w := range v.Warnings[nWarn:] {
		s.warn(w)
	}
	return err
}
