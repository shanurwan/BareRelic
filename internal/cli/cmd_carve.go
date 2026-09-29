package cli

import (
	"flag"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/shanurwan/barerelic/internal/carve"
	"github.com/shanurwan/barerelic/internal/evidence"
	"github.com/shanurwan/barerelic/internal/extent"
)

type carveOpts struct {
	Types   []string `json:"types"`
	Align   int64    `json:"align"`
	Offset  int64    `json:"offset"`
	Length  int64    `json:"length"`
	NoSkip  bool     `json:"no_skip"`
	MinSize int64    `json:"min_size"`
}

func runCarve(a *app, args []string) int {
	fs := flag.NewFlagSet("carve", flag.ContinueOnError)
	var c common
	c.register(fs)
	out := fs.String("out", "", "case directory to create (must not exist or be empty)")
	types := fs.String("types", "", "comma-separated types (default all): "+strings.Join(carve.Names(), ","))
	var o carveOpts
	fs.Int64Var(&o.Align, "align", 512, "candidate alignment in bytes; 1 also finds files embedded at arbitrary offsets (slower)")
	fs.Int64Var(&o.Offset, "offset", 0, "start of the range to carve")
	fs.Int64Var(&o.Length, "length", 0, "length of the range to carve (default: to the end)")
	fs.BoolVar(&o.NoSkip, "no-skip", false, "keep scanning inside carved files (finds embedded thumbnails/archives)")
	fs.Int64Var(&o.MinSize, "min-size", 0, "ignore carved files smaller than this")
	mapPath := fs.String("map", "", "rescue map of the image; files touching unreadable regions are flagged")
	list := fs.Bool("list-types", false, "list supported types and exit")
	pos, ok := a.parse(fs, &c, args, "<source>")
	if !ok {
		return ExitUsage
	}
	if *list {
		for _, s := range carve.Signatures {
			fmt.Fprintf(a.stdout, "%-8s .%-6s max %s\n", s.Name, s.Ext, humanBytes(s.MaxSize))
		}
		return ExitOK
	}
	if len(pos) != 1 || *out == "" {
		return a.usageErr(fs, "a source and --out are required")
	}
	if o.Align <= 0 {
		return a.usageErr(fs, "--align must be positive")
	}
	if *types != "" {
		o.Types = strings.Split(*types, ",")
	}
	sigs, err := carve.Lookup(o.Types)
	if err != nil {
		return a.usageErr(fs, "%v", err)
	}
	src, err := a.openSource(pos[0])
	if err != nil {
		return a.fail(err)
	}
	defer src.Close()
	if err := checkOutputSeparate(src, *out); err != nil {
		return a.fail(err)
	}
	m, err := loadMap(*mapPath, src)
	if err != nil {
		return a.fail(err)
	}
	end := int64(0)
	if o.Length > 0 {
		end = o.Offset + o.Length
	}
	cs, err := evidence.Create(*out, a.header("carve", &c, src, *mapPath, o))
	if err != nil {
		return a.fail(err)
	}

	p := newProgress(a, "carving", max(end, src.Size()))
	if end > 0 {
		p.total = end
	}
	var failed, unreadableFiles int
	st, scanErr := carve.Scan(a.ctx, src, src.Size(), carve.Options{
		Signatures: sigs, Align: o.Align, Start: o.Offset, End: end, NoSkip: o.NoSkip, MinSize: o.MinSize, Progress: p.update,
	}, func(mt carve.Match) error {
		conf := evidence.High
		if mt.Validation == carve.Heuristic {
			conf = evidence.Medium
		}
		art := evidence.Artifact{
			Method: "carve:" + mt.Type, State: "carved", Confidence: conf, Type: mt.Ext,
			Extents: extent.List{{Offset: mt.Offset, Length: mt.Length}},
			Notes:   append([]string{"validation: " + mt.Validation, "contiguous allocation assumed"}, mt.Notes...),
		}
		annotate(&art, m)
		if art.Unreadable > 0 {
			unreadableFiles++
		}
		rel := path.Join("carved", mt.Ext, fmt.Sprintf("%012X.%s", mt.Offset, mt.Ext))
		if _, err := cs.AddFile(rel, io.NewSectionReader(src, mt.Offset, mt.Length), art); err != nil {
			failed++
			a.log.Warn("carve extraction failed", "offset", mt.Offset, "err", err)
		}
		return nil
	})
	if st.ReadErrors > 0 {
		_ = cs.Warn(fmt.Sprintf("%d unreadable sectors were zero-filled during scanning; image the media first", st.ReadErrors))
	}
	result, code := outcome(failed > 0 || unreadableFiles > 0 || st.ReadErrors > 0)
	if scanErr != nil {
		result, code = "failed", ExitFailure
		if a.ctx.Err() != nil {
			result, code = "interrupted", ExitInterrupted
		}
	}
	man, err := cs.Close(result, st)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "case:       %s\noutcome:    %s\ncarved:     %d files (%s)\n", *out, man.Outcome, man.Artifacts, humanBytes(man.Bytes))
	for _, k := range sortedKeys(st.Carved) {
		fmt.Fprintf(a.stdout, "  %-8s %d\n", k, st.Carved[k])
	}
	fmt.Fprintf(a.stdout, "candidates: %d (rejected by validation: %d)\n", st.Candidates, sum(st.Rejected))
	if scanErr != nil {
		return a.fail(scanErr)
	}
	return code
}

func sum(m map[string]int64) int64 {
	var n int64
	for _, v := range m {
		n += v
	}
	return n
}
