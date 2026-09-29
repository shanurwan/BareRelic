//go:build !windows

package rescuemap

import "os"

// syncDir makes a rename durable on POSIX filesystems. Best effort.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}
