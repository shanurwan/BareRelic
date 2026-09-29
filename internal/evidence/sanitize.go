package evidence

import (
	"path"
	"strings"
	"unicode/utf8"
)

// maxComponentBytes keeps names well under common 255-byte filesystem limits
// after collision suffixes are appended.
const maxComponentBytes = 200

var windowsReserved = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// SanitizeComponent turns an untrusted file name recovered from evidence into
// a single safe path component on every supported host OS. It never returns
// "", ".", ".." or a name containing a separator.
func SanitizeComponent(name string) string {
	if !utf8.ValidString(name) {
		name = strings.ToValidUTF8(name, "_")
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7F:
			b.WriteByte('_')
		case strings.ContainsRune(`<>:"/\|?*`, r):
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	s := b.String()
	// Windows silently strips trailing dots and spaces, which would alias names.
	if trimmed := strings.TrimRight(s, ". "); trimmed != s {
		s = trimmed + strings.Repeat("_", len(s)-len(trimmed))
	}
	if s == "" || s == "." || s == ".." {
		return "_"
	}
	base := strings.ToUpper(s)
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	if windowsReserved[base] {
		s = "_" + s
	}
	if len(s) > maxComponentBytes {
		cut := maxComponentBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return s
}

// SanitizePath sanitises every component of a slash- or backslash-separated
// recovered path and returns a relative, slash-separated path that cannot
// escape its root.
func SanitizePath(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	var parts []string
	for _, c := range strings.Split(p, "/") {
		if c == "" || c == "." {
			continue
		}
		parts = append(parts, SanitizeComponent(c))
	}
	if len(parts) == 0 {
		return "_"
	}
	return path.Join(parts...)
}
