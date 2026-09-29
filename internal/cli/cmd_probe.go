package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/shanurwan/barerelic/internal/fsdetect"
	"github.com/shanurwan/barerelic/internal/volume"
)

// volumeInfo is a partition (or whole-disk volume) with its file system.
type volumeInfo struct {
	volume.Partition
	FS     *fsdetect.FS `json:"fs,omitempty"`
	Lost   bool         `json:"lost,omitempty"`
	Source string       `json:"found_by"`
}

type probeReport struct {
	Source     string               `json:"source"`
	Size       int64                `json:"size"`
	SectorSize int                  `json:"sector_size"`
	Table      *volume.Table        `json:"table,omitempty"`
	Volumes    []volumeInfo         `json:"volumes"`
	Scan       []fsdetect.Candidate `json:"scan,omitempty"`
	Warnings   []string             `json:"warnings,omitempty"`
}

// discoverVolumes finds volumes from the partition table, or treats the
// whole source as one volume when it starts with a file system ("super
// floppy" layout used by many USB sticks and memory cards).
func discoverVolumes(r io.ReaderAt, size int64, sector int) ([]volumeInfo, *volume.Table, []string) {
	var warnings []string
	if fs, ok := fsdetect.Identify(r, 0); ok {
		return []volumeInfo{{Partition: volume.Partition{Index: 0, Scheme: volume.SchemeNone, Start: 0, Size: size, Type: "whole-disk"},
			FS: &fs, Source: "file system at offset 0 (no partition table)"}}, nil, nil
	}
	tab, err := volume.Read(r, size, sector)
	if err != nil {
		if !errors.Is(err, volume.ErrNoTable) {
			warnings = append(warnings, "partition table: "+err.Error())
		} else {
			warnings = append(warnings, "no partition table and no file system at offset 0; try `probe --scan`")
		}
		return nil, nil, warnings
	}
	var out []volumeInfo
	for _, p := range tab.Partitions {
		v := volumeInfo{Partition: p, Source: string(tab.Scheme) + " partition table"}
		if fs, ok := fsdetect.Identify(r, p.Start); ok {
			v.FS = &fs
		}
		out = append(out, v)
	}
	return out, tab, append(warnings, tab.Warnings...)
}

func runProbe(a *app, args []string) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	var c common
	c.register(fs)
	scan := fs.Bool("scan", false, "scan the whole source for lost/deleted partitions (reads every sector)")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	pos, ok := a.parse(fs, &c, args, "<source>")
	if !ok {
		return ExitUsage
	}
	if len(pos) != 1 {
		return a.usageErr(fs, "exactly one source is required")
	}
	src, err := a.openSource(pos[0])
	if err != nil {
		return a.fail(err)
	}
	defer src.Close()

	rep := probeReport{Source: src.Path(), Size: src.Size(), SectorSize: src.SectorSize()}
	rep.Volumes, rep.Table, rep.Warnings = discoverVolumes(src, src.Size(), src.SectorSize())

	if *scan {
		p := newProgress(a, "scanning for lost partitions", src.Size())
		cands, err := fsdetect.ScanLost(a.ctx, src, src.Size(), fsdetect.ScanOptions{Progress: p.update})
		if err != nil {
			return a.fail(err)
		}
		rep.Scan = cands
		for _, cand := range cands {
			listed := false
			for _, v := range rep.Volumes {
				if v.Start == cand.Start {
					listed = true
				}
			}
			if !listed && cand.Confidence != "low" {
				fs := cand.FS
				rep.Volumes = append(rep.Volumes, volumeInfo{
					Partition: volume.Partition{Index: -1, Start: cand.Start, Size: cand.FS.Size, Type: "lost"},
					FS:        &fs, Lost: true, Source: cand.Evidence,
				})
			}
		}
	}

	if *asJSON {
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return a.fail(err)
		}
		return ExitOK
	}
	fmt.Fprintf(a.stdout, "source: %s (%s, %d-byte sectors)\n", rep.Source, humanBytes(rep.Size), rep.SectorSize)
	if rep.Table != nil {
		fmt.Fprintf(a.stdout, "scheme: %s", rep.Table.Scheme)
		if rep.Table.DiskGUID != "" {
			fmt.Fprintf(a.stdout, " (disk %s)", rep.Table.DiskGUID)
		}
		fmt.Fprintln(a.stdout)
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\n#\tSTART\tSIZE\tTYPE\tFS\tLABEL/NAME\tRECOVER\tFOUND BY")
	for _, v := range rep.Volumes {
		idx := fmt.Sprint(v.Index)
		if v.Lost {
			idx = "lost"
		}
		fsType, label, rec := "-", v.Name, "no"
		if v.FS != nil {
			fsType = v.FS.Type
			if v.FS.Label != "" {
				label = v.FS.Label
			}
			if v.FS.Recoverable {
				rec = "yes"
			}
		}
		typ := v.TypeName
		if typ == "" {
			typ = v.Type
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n", idx, v.Start, humanBytes(v.Size), typ, fsType, label, rec, v.Source)
	}
	tw.Flush()
	if len(rep.Volumes) > 0 {
		fmt.Fprintln(a.stdout, "\nRecover with: barerelic recover --partition <#> (or --offset <START> for lost volumes) --out <dir> <source>")
	}
	for _, w := range rep.Warnings {
		fmt.Fprintln(a.stdout, "warning:", w)
	}
	return ExitOK
}
