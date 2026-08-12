// Copyright Jetstack Ltd. See LICENSE for details.
package cache

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mapping.json")

	store, err := NewFile(path)
	if err != nil {
		t.Fatalf("unexpected error building store: %s", err)
	}

	// Nothing has been persisted yet, which is the ordinary first start.
	if _, err := store.Load(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	if err := store.Save(context.Background(), []byte("first")); err != nil {
		t.Fatalf("unexpected error saving: %s", err)
	}

	data, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("unexpected error loading: %s", err)
	}
	if string(data) != "first" {
		t.Errorf("expected \"first\", got %q", data)
	}

	if err := store.Save(context.Background(), []byte("second")); err != nil {
		t.Fatalf("unexpected error saving: %s", err)
	}

	data, err = store.Load(context.Background())
	if err != nil {
		t.Fatalf("unexpected error loading: %s", err)
	}
	if string(data) != "second" {
		t.Errorf("expected the save to have replaced the mapping, got %q", data)
	}
}

// The mapping names every user of the cluster, so it must not be left readable
// to anything else sharing the volume.
func TestFileIsWrittenPrivately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mapping.json")

	store, err := NewFile(path)
	if err != nil {
		t.Fatalf("unexpected error building store: %s", err)
	}

	if err := store.Save(context.Background(), []byte("mapping")); err != nil {
		t.Fatalf("unexpected error saving: %s", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("unexpected error stating the mapping: %s", err)
	}

	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected mode 0600, got %04o", perm)
	}
}

// The proxy is often given a path in an empty volume.
func TestFileCreatesItsDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "deeper")

	store, err := NewFile(filepath.Join(dir, "mapping.json"))
	if err != nil {
		t.Fatalf("unexpected error building store: %s", err)
	}

	if err := store.Save(context.Background(), []byte("mapping")); err != nil {
		t.Fatalf("unexpected error saving: %s", err)
	}

	if _, err := store.Load(context.Background()); err != nil {
		t.Errorf("unexpected error loading: %s", err)
	}
}

// A save that is interrupted part way through must not leave a truncated file
// to be read back at the next startup, so nothing is written in place.
func TestFileSaveLeavesNoTemporaryFilesBehind(t *testing.T) {
	dir := t.TempDir()

	store, err := NewFile(filepath.Join(dir, "mapping.json"))
	if err != nil {
		t.Fatalf("unexpected error building store: %s", err)
	}

	if err := store.Save(context.Background(), []byte("mapping")); err != nil {
		t.Fatalf("unexpected error saving: %s", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("unexpected error reading the directory: %s", err)
	}

	if len(entries) != 1 || entries[0].Name() != "mapping.json" {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}

		t.Errorf("expected only the mapping to be left behind, got %v", names)
	}
}

// A zero length file is what an interrupted write by an older proxy, or a
// freshly provisioned volume, leaves behind.
func TestFileTreatsAnEmptyFileAsNothingPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mapping.json")

	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatalf("unexpected error writing the mapping: %s", err)
	}

	store, err := NewFile(path)
	if err != nil {
		t.Fatalf("unexpected error building store: %s", err)
	}

	if _, err := store.Load(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestNewFileRejectsAnEmptyPath(t *testing.T) {
	if _, err := NewFile(""); err == nil {
		t.Error("expected an error building a store with no path")
	}
}
