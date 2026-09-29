// Package buildinfo reports the identity of the running binary so that every
// evidence record can name the exact tool build that produced it.
package buildinfo

import (
	"runtime"
	"runtime/debug"
)

// Version is overridden at link time: -ldflags "-X github.com/shanurwan/barerelic/internal/buildinfo.Version=v0.1.0".
var Version = "dev"

// Info identifies a build.
type Info struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Revision  string `json:"revision,omitempty"`
	Modified  bool   `json:"modified,omitempty"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Get returns the build identity, including the VCS revision stamped by the Go
// toolchain when built from a Git checkout.
func Get() Info {
	info := Info{
		Name:      "barerelic",
		Version:   Version,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				info.Revision = s.Value
			case "vcs.modified":
				info.Modified = s.Value == "true"
			}
		}
	}
	return info
}
