package utils

import (
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"
)

// ErrUnsafePath is returned when a feed-supplied name can't be used as a
// path element without escaping the directory it is meant to live in.
var ErrUnsafePath = xerrors.New("unsafe path")

// ValidatePathComponent checks that name, which usually comes straight from
// an advisory feed (an advisory ID, a package name, a release), is a single
// path element. Empty names, "." and "..", names containing a path separator
// (either / or \, whatever the host OS) or a NUL byte, and names carrying a
// volume prefix are rejected.
func ValidatePathComponent(name string) error {
	switch {
	case name == "":
		return xerrors.Errorf("empty path component: %w", ErrUnsafePath)
	case name == "." || name == "..":
		return xerrors.Errorf("%q is a relative path reference: %w", name, ErrUnsafePath)
	case strings.ContainsAny(name, "/\\\x00"):
		return xerrors.Errorf("%q contains a path separator or NUL byte: %w", name, ErrUnsafePath)
	case filepath.VolumeName(name) != "":
		return xerrors.Errorf("%q contains a volume name: %w", name, ErrUnsafePath)
	}
	return nil
}

// SafeJoin joins elems onto base like filepath.Join, but only after checking
// that every element is a single safe path component, and it verifies that the
// cleaned result still lies strictly under base. Use it whenever a value read
// from a feed becomes part of a file path.
func SafeJoin(base string, elems ...string) (string, error) {
	for _, elem := range elems {
		if err := ValidatePathComponent(elem); err != nil {
			return "", err
		}
	}

	cleanBase := filepath.Clean(base)
	joined := filepath.Join(append([]string{cleanBase}, elems...)...)
	rel, err := filepath.Rel(cleanBase, joined)
	if err != nil {
		return "", xerrors.Errorf("%s is not under %s (%v): %w", joined, cleanBase, err, ErrUnsafePath)
	}
	if len(elems) > 0 && (rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel)) {
		return "", xerrors.Errorf("%s is not under %s: %w", joined, cleanBase, ErrUnsafePath)
	}
	return joined, nil
}
