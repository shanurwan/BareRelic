package cli

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/shanurwan/barerelic/internal/buildinfo"
	"github.com/shanurwan/barerelic/internal/evidence"
)

func runHash(a *app, args []string) int {
	fs := flag.NewFlagSet("hash", flag.ContinueOnError)
	var c common
	c.register(fs)
	asJSON := fs.Bool("json", false, "print JSON")
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
	hm, h1, h256 := md5.New(), sha1.New(), sha256.New()
	w := io.MultiWriter(hm, h1, h256)
	p := newProgress(a, "hashing", src.Size())
	buf := make([]byte, 4<<20)
	for off := int64(0); off < src.Size(); {
		if err := a.ctx.Err(); err != nil {
			return a.fail(err)
		}
		n, err := src.ReadAt(buf[:min(int64(len(buf)), src.Size()-off)], off)
		w.Write(buf[:n])
		off += int64(n)
		if err != nil && !(errors.Is(err, io.EOF) && off == src.Size()) {
			return a.fail(fmt.Errorf("read error at offset %d: %w (image failing media with `barerelic image` first)", off, err))
		}
		p.update(off)
	}
	res := map[string]any{
		"source": src.Path(), "size": src.Size(),
		"md5":    hex.EncodeToString(hm.Sum(nil)),
		"sha1":   hex.EncodeToString(h1.Sum(nil)),
		"sha256": hex.EncodeToString(h256.Sum(nil)),
	}
	if *asJSON {
		json.NewEncoder(a.stdout).Encode(res)
		return ExitOK
	}
	fmt.Fprintf(a.stdout, "md5     %s\nsha1    %s\nsha256  %s\nsize    %d\nsource  %s\n", res["md5"], res["sha1"], res["sha256"], src.Size(), src.Path())
	return ExitOK
}

func runVerify(a *app, args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	var c common
	c.register(fs)
	pos, ok := a.parse(fs, &c, args, "<case-dir | image>")
	if !ok {
		return ExitUsage
	}
	if len(pos) != 1 {
		return a.usageErr(fs, "exactly one case directory or image is required")
	}
	target := pos[0]
	st, err := os.Stat(target)
	if err != nil {
		return a.fail(err)
	}
	if !st.IsDir() {
		return a.verifyImage(target)
	}
	rep, err := evidence.Verify(target)
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "journal entries: %d\nartifacts:       %d\nverified:        %d\n", rep.Entries, rep.Artifacts, rep.Verified)
	for _, p := range rep.Problems {
		fmt.Fprintln(a.stdout, "PROBLEM:", p)
	}
	if !rep.OK() {
		fmt.Fprintln(a.stdout, "result:          FAILED")
		return ExitPartial
	}
	fmt.Fprintln(a.stdout, "result:          OK")
	return ExitOK
}

func (a *app) verifyImage(img string) int {
	sidecar := img + ".barerelic.json"
	b, err := os.ReadFile(sidecar)
	if err != nil {
		return a.fail(fmt.Errorf("no acquisition record %s: %w", filepath.Base(sidecar), err))
	}
	var rec acquisition
	if err := json.Unmarshal(b, &rec); err != nil {
		return a.fail(err)
	}
	if rec.ImageSHA256 == "" {
		return a.fail(errors.New("acquisition record has no image hash (run was interrupted or used --no-hash)"))
	}
	f, err := os.Open(img)
	if err != nil {
		return a.fail(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return a.fail(err)
	}
	sum, err := a.hashFile(f, st.Size())
	if err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "recorded: %s\ncomputed: %s\n", rec.ImageSHA256, sum)
	if sum != rec.ImageSHA256 {
		fmt.Fprintln(a.stdout, "result:   FAILED (image changed since acquisition)")
		return ExitPartial
	}
	fmt.Fprintln(a.stdout, "result:   OK")
	return ExitOK
}

func runVersion(a *app, args []string) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	if _, ok := a.parse(fs, nil, args, ""); !ok {
		return ExitUsage
	}
	bi := buildinfo.Get()
	if *asJSON {
		json.NewEncoder(a.stdout).Encode(bi)
		return ExitOK
	}
	rev := bi.Revision
	if rev == "" {
		rev = "unknown"
	} else if bi.Modified {
		rev += "-dirty"
	}
	fmt.Fprintf(a.stdout, "barerelic %s (revision %s, %s, %s/%s)\n", bi.Version, rev, bi.GoVersion, bi.OS, bi.Arch)
	return ExitOK
}
