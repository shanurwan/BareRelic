// Command barerelic is a bare-metal data recovery and forensic
// reconstruction tool. See README.md.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/shanurwan/barerelic/internal/cli"
)

func main() {
	// The first SIGINT/SIGTERM cancels the context so long operations can
	// checkpoint (rescue map, journal) and exit cleanly; a second one kills
	// the process via the default handler once stop() has run.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		stop()
	}()
	os.Exit(cli.Run(ctx, os.Args, os.Stdout, os.Stderr))
}
