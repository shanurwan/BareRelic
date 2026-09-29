// Package cli implements the barerelic command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"
)

// Exit codes. They are part of the public interface; see docs/operations.md.
const (
	ExitOK          = 0
	ExitFailure     = 1   // the operation could not be performed
	ExitUsage       = 2   // bad invocation
	ExitPartial     = 3   // completed, but some data was unreadable/unrecoverable, or verification found problems
	ExitInterrupted = 130 // cancelled (SIGINT/SIGTERM); state was checkpointed
)

type app struct {
	ctx    context.Context
	stdout io.Writer
	stderr io.Writer
	log    *slog.Logger
	args   []string // full command line, for provenance
}

type command struct {
	name    string
	summary string
	run     func(a *app, args []string) int
}

func commands() []command {
	return []command{
		{"image", "acquire a forensic image from a (possibly failing) disk, resumably", runImage},
		{"probe", "show partitions and file systems; --scan finds lost partitions", runProbe},
		{"recover", "recover deleted (or all) files through FAT/NTFS metadata", runRecover},
		{"carve", "recover files by content signatures, without file-system metadata", runCarve},
		{"hash", "hash a source (MD5, SHA-1, SHA-256) in one pass", runHash},
		{"verify", "re-verify a case directory or an image against its record", runVerify},
		{"version", "print build information", runVersion},
	}
}

// Run executes the command line and returns the process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	a := &app{ctx: ctx, stdout: stdout, stderr: stderr, args: args}
	if len(args) < 2 || args[1] == "-h" || args[1] == "--help" || args[1] == "help" {
		a.usage()
		if len(args) < 2 {
			return ExitUsage
		}
		return ExitOK
	}
	for _, c := range commands() {
		if c.name == args[1] {
			return c.run(a, args[2:])
		}
	}
	fmt.Fprintf(stderr, "barerelic: unknown command %q\n\n", args[1])
	a.usage()
	return ExitUsage
}

func (a *app) usage() {
	fmt.Fprintln(a.stderr, `barerelic — bare-metal data recovery and forensic reconstruction

Usage: barerelic <command> [flags] <source>

Sources are opened strictly read-only: image files, or raw devices such as
/dev/sdb, /dev/rdisk2 or \\.\PhysicalDrive1. Image failing media first
("barerelic image") and run every other command against the image.

Commands:`)
	for _, c := range commands() {
		fmt.Fprintf(a.stderr, "  %-8s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(a.stderr, `
Run "barerelic <command> -h" for command flags.
Exit codes: 0 ok, 1 failure, 2 usage, 3 partial/unverified, 130 interrupted.`)
}

// common holds flags shared by every command.
type common struct {
	logLevel  string
	logFormat string
	caseID    string
	examiner  string
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.logLevel, "log-level", "info", "log level: debug, info, warn, error")
	fs.StringVar(&c.logFormat, "log-format", "text", "log format on stderr: text or json")
	fs.StringVar(&c.caseID, "case", "", "case identifier recorded in evidence")
	fs.StringVar(&c.examiner, "examiner", "", "examiner name recorded in evidence")
}

func (a *app) setupLog(c *common) error {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(c.logLevel)); err != nil {
		return fmt.Errorf("bad --log-level %q", c.logLevel)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	switch c.logFormat {
	case "text":
		a.log = slog.New(slog.NewTextHandler(a.stderr, opts))
	case "json":
		a.log = slog.New(slog.NewJSONHandler(a.stderr, opts))
	default:
		return fmt.Errorf("bad --log-format %q", c.logFormat)
	}
	return nil
}

// parse parses flags and returns positional arguments; it reports usage
// errors itself and returns ok=false.
func (a *app) parse(fs *flag.FlagSet, c *common, args []string, positional string) ([]string, bool) {
	fs.SetOutput(a.stderr)
	fs.Usage = func() {
		fmt.Fprintf(a.stderr, "Usage: barerelic %s [flags] %s\n\nFlags:\n", fs.Name(), positional)
		fs.PrintDefaults()
	}
	// Allow flags after positional arguments (barerelic carve img.dd --out x).
	var flagsFirst, pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			flagsFirst = append(flagsFirst, arg)
			name := strings.TrimLeft(arg, "-")
			if !strings.Contains(name, "=") {
				if f := fs.Lookup(name); f != nil {
					if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok || !bf.IsBoolFlag() {
						if i+1 < len(args) {
							flagsFirst = append(flagsFirst, args[i+1])
							i++
						}
					}
				}
			}
			continue
		}
		pos = append(pos, arg)
	}
	if err := fs.Parse(flagsFirst); err != nil {
		return nil, false
	}
	if c != nil {
		if err := a.setupLog(c); err != nil {
			fmt.Fprintln(a.stderr, "barerelic:", err)
			return nil, false
		}
	}
	return pos, true
}

func (a *app) fail(err error) int {
	if errors.Is(err, context.Canceled) {
		a.log.Warn("interrupted; state checkpointed")
		return ExitInterrupted
	}
	a.log.Error("failed", "err", err)
	return ExitFailure
}

func (a *app) usageErr(fs *flag.FlagSet, format string, args ...any) int {
	fmt.Fprintf(a.stderr, "barerelic %s: %s\n\n", fs.Name(), fmt.Sprintf(format, args...))
	fs.Usage()
	return ExitUsage
}

// progress rate-limits progress callbacks into log lines.
type progress struct {
	a       *app
	what    string
	total   int64
	every   time.Duration
	started time.Time
	last    time.Time
}

func newProgress(a *app, what string, total int64) *progress {
	now := time.Now()
	return &progress{a: a, what: what, total: total, every: 5 * time.Second, started: now, last: now}
}

func (p *progress) update(pos int64) {
	now := time.Now()
	if now.Sub(p.last) < p.every && pos < p.total {
		return
	}
	p.last = now
	elapsed := now.Sub(p.started).Seconds()
	rate := float64(pos) / max(elapsed, 1e-9)
	eta := time.Duration(0)
	if rate > 0 {
		eta = time.Duration(float64(p.total-pos)/rate) * time.Second
	}
	p.a.log.Info(p.what, "pos", pos, "total", p.total,
		"pct", fmt.Sprintf("%.1f", 100*float64(pos)/float64(max(p.total, 1))),
		"rate", humanBytes(int64(rate))+"/s", "eta", eta.Round(time.Second).String())
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
