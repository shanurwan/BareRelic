//go:build windows

package rescuemap

// syncDir is a no-op on Windows: NTFS journals the rename metadata and
// directory handles cannot be fsynced through the os package.
func syncDir(string) {}
