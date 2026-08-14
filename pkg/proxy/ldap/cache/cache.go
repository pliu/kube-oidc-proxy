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

	// Save replaces the persisted payload. The fingerprint identifies the
	// mapping the payload holds - not the payload itself, which carries a
	// build time that moves whether or not the mapping has - so that a store
	// shared by more than one proxy can tell what it is already holding. A
	// store is free to ignore it.
	Save(ctx context.Context, data []byte, fingerprint string) error

	// String describes the store well enough to identify it in a log line.
	String() string
}

// Fingerprinter is a store that can say which mapping it holds without being
// made to hand the mapping over. A proxy serving what another one built polls
// this, and fetches the mapping itself only when the answer changes - which
// keeps a megabyte off the wire on every poll but the ones that matter.
//
// It returns ErrNotFound when the store holds nothing, and an empty
// fingerprint when it holds a mapping that was written without one.
type Fingerprinter interface {
	Fingerprint(ctx context.Context) (string, error)
}

// Watcher is a store that can say when the mapping it holds has changed rather
// than waiting to be asked, so that a proxy serving what another one built
// picks it up as it lands instead of at the next poll.
//
// onChange is called with the fingerprint the store now holds, so that a
// caller already serving that mapping can do nothing without going back to the
// store to find out. It is called from a goroutine of the store's own, and may
// be called with a fingerprint that has not changed.
type Watcher interface {
	// Watch delivers changes until stopCh is closed. It returns once it is
	// established, so that a caller knows changes from that point are not
	// being missed, or an error if it cannot be.
	Watch(stopCh <-chan struct{}, onChange func(fingerprint string)) error
}
