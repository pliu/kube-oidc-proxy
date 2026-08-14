// Copyright Jetstack Ltd. See LICENSE for details.
package cache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// File persists the mapping to a file on disk. Intended to be pointed at a
// volume that outlives the container, such as a PersistentVolumeClaim or a
// host path.
type File struct {
	path string
}

var _ Store = &File{}

func NewFile(path string) (*File, error) {
	if path == "" {
		return nil, errors.New("no path configured for the file mapping cache")
	}

	return &File{path: path}, nil
}

func (f *File) Load(_ context.Context) ([]byte, error) {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %s", f.path, err)
	}

	// A zero length file is what a truncated write leaves behind, and holds no
	// mapping either way.
	if len(data) == 0 {
		return nil, ErrNotFound
	}

	return data, nil
}

// Save writes to a temporary file in the same directory and renames it over
// the target, so that a crash part way through a write cannot leave a half
// written mapping to be read back at startup.
//
// The fingerprint is ignored. Keeping it beside the mapping would mean a
// second file that can disagree with the first, and a reader of a file - which
// is local, and served from the page cache - loses little by reading the
// mapping itself to find out whether it changed.
func (f *File) Save(_ context.Context, data []byte, _ string) error {
	dir := filepath.Dir(f.path)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %q: %s", dir, err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(f.path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create a temporary file in %q: %s", dir, err)
	}
	// Cleans up the temporary file on every path that does not reach the
	// rename below. Once renamed, the remove finds nothing and is a no-op.
	defer os.Remove(tmp.Name())

	// The mapping names every user of the cluster, so keep it to the owner
	// rather than whatever the umask allows.
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to set the permissions of %q: %s", tmp.Name(), err)
	}

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write %q: %s", tmp.Name(), err)
	}

	// Flush to disk before the rename, so that the rename cannot be visible
	// while the contents it points at are not.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to flush %q: %s", tmp.Name(), err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close %q: %s", tmp.Name(), err)
	}

	if err := os.Rename(tmp.Name(), f.path); err != nil {
		return fmt.Errorf("failed to move %q into place at %q: %s", tmp.Name(), f.path, err)
	}

	return nil
}

func (f *File) String() string {
	return fmt.Sprintf("file %q", f.path)
}
