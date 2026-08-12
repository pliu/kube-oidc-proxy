// Copyright Jetstack Ltd. See LICENSE for details.

// Package cache persists the user to group mapping built from the configured
// directories, so that a proxy that is restarted while those directories are
// unreachable can still serve the last mapping it built rather than stripping
// every user of their groups.
package cache

import (
	"context"
	"errors"
)

// ErrNotFound is returned by Load when nothing has been persisted yet. It is
// an ordinary state on a first start, not a failure.
var ErrNotFound = errors.New("no persisted mapping found")

// Store is where a built mapping is kept between restarts. Implementations
// hold an opaque payload: what is in it, and how it is versioned, is the
// concern of the caller.
type Store interface {
	// Load returns the payload last passed to Save, or ErrNotFound if there is
	// nothing to return.
	Load(ctx context.Context) ([]byte, error)

	// Save replaces the persisted payload.
	Save(ctx context.Context, data []byte) error

	// String describes the store well enough to identify it in a log line.
	String() string
}
