package ntfs

import (
	"bytes"
	"context"
	"fmt"
	"path"
)

// scanOrphanRecords finds FILE records anywhere on the volume outside the
// current MFT and $MFTMirr. After a quick format Windows writes a fresh, small
// MFT; records of the previous file system survive wherever they were not
// overwritten. Their non-resident runlists are interpreted with the current
// cluster size, which a reformat with default options preserves.
func (v *Volume) scanOrphanRecords(ctx context.Context, opt WalkOptions, fn func(File) error) error {
	cs := v.Boot.ClusterSize()
	rs := int64(v.Boot.RecordSize)
	step := min(rs, cs)

	type span struct{ lo, hi int64 }
	var skip []span
	for _, r := range v.mftRuns {
		if r.LCN >= 0 {
			skip = append(skip, span{r.LCN * cs, (r.LCN + r.Length) * cs})
		}
	}
	mirr := int64(v.Boot.MFTMirrCluster) * cs
	skip = append(skip, span{mirr, mirr + 4*rs})
	inSkip := func(off int64) bool {
		for _, s := range skip {
			if off >= s.lo && off < s.hi {
				return true
			}
		}
		return false
	}

	const chunk = 8 << 20
	buf := make([]byte, chunk+rs)
	limit := min(v.size, v.Boot.VolumeSize())
	found := 0
	for base := int64(0); base < limit; base += chunk {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, _ := v.r.ReadAt(buf[:min(int64(len(buf)), limit-base)], base)
		for i := int64(0); i+rs <= int64(n) && i < chunk; i += step {
			if !bytes.Equal(buf[i:i+4], []byte("FILE")) || inSkip(base+i) {
				continue
			}
			rec, err := ParseRecord(buf[i : i+rs])
			if err != nil || rec.BaseRef != 0 || rec.IsDir() {
				continue
			}
			if rec.HasNumber && rec.Number < firstUserRec && !opt.IncludeSystem {
				continue
			}
			// Records of a previous MFT may still carry the in-use flag; they are
			// unreachable all the same, so they are reported regardless of scope.
			f := v.orphanFile(rec, base+i)
			if f.Name == "" {
				continue
			}
			found++
			if err := fn(f); err != nil {
				return err
			}
		}
	}
	if found > 0 {
		v.Warnings = append(v.Warnings, fmt.Sprintf("deep scan recovered %d MFT records from outside the current MFT", found))
	}
	return nil
}

func (v *Volume) orphanFile(rec *Record, off int64) File {
	fn, _ := preferredName(fileNames(rec))
	f := File{
		Record:       rec.Number,
		Sequence:     rec.Sequence,
		RecordOffset: off,
		Name:         fn.Name,
		Deleted:      true,
		Orphan:       true,
		OutsideMFT:   true,
		Created:      fn.Created, Modified: fn.Modified, Accessed: fn.Accessed, MFTChange: fn.MFTChange,
	}
	for _, a := range rec.Attrs {
		if a.Type == AttrStandardInformation && !a.NonResident {
			if si, ok := parseStdInfo(a.Value); ok {
				f.Created, f.Modified, f.Accessed, f.MFTChange = si.Created, si.Modified, si.Accessed, si.MFTChange
			}
		}
	}
	offs := make([]int64, len(rec.Attrs))
	for i := range offs {
		offs[i] = off
	}
	f.Streams = collectStreams(rec.Attrs, offs)
	f.Path = path.Join("/$OrphanRecords", fmt.Sprintf("off_%X_%s", off, fn.Name))
	f.Notes = append(f.Notes, fmt.Sprintf("MFT record found at volume offset 0x%X outside the current MFT (e.g. left by a format); original path unknown; cluster size assumed unchanged", off))
	for _, a := range rec.Attrs {
		if a.Type == AttrAttributeList {
			f.Notes = append(f.Notes, "record has an attribute list; streams stored in extension records are not recoverable from an orphan record")
			break
		}
	}
	return f
}
