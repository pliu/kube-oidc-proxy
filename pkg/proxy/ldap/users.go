// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/klog/v2"
)

type userCell struct {
	entry   cache.UserEntry
	deleted bool
}

// UserDirectory serves per-user persisted records. Its map lock protects only
// memory; LDAP and Kubernetes work happen outside it.
type UserDirectory struct {
	leadership func() context.Context
	callsMu    sync.Mutex
	calls      map[string]*userCall
	resolver   *resolver
	store      cache.UserStore
	mu         sync.RWMutex
	users      map[string]userCell // keyed by deterministic object name, including tombstones
	synced     atomic.Bool
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewUserDirectory refreshes cached users periodically only during the live
// leadership term returned by leadership; nil denotes a follower.
func NewUserDirectory(config *Config, store cache.UserStore, leadership func() context.Context) (*UserDirectory, error) {
	if store == nil {
		return nil, fmt.Errorf("per-user LDAP cache requires ConfigMap persistence")
	}
	if leadership == nil {
		return nil, fmt.Errorf("per-user LDAP cache requires a leadership context provider")
	}
	resolver, err := newResolver(config)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &UserDirectory{leadership: leadership, resolver: resolver, store: store, users: make(map[string]userCell), calls: make(map[string]*userCall), ctx: ctx, cancel: cancel}, nil
}

// Core Kubernetes ConfigMap resource versions are monotonically increasing
// decimal revisions. Treat equality as idempotent and never regress memory.
func newerVersion(incoming, current string) bool {
	if current == "" {
		return true
	}
	if incoming == current {
		return false
	}
	a, okA := new(big.Int).SetString(incoming, 10)
	b, okB := new(big.Int).SetString(current, 10)
	return okA && okB && a.Cmp(b) > 0
}

func (d *UserDirectory) apply(entry cache.UserEntry, deleted bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.applyLocked(entry, deleted)
}
func (d *UserDirectory) applyLocked(entry cache.UserEntry, deleted bool) {
	current, exists := d.users[entry.Name]
	if exists && !newerVersion(entry.ResourceVersion, current.entry.ResourceVersion) && !(deleted && !current.deleted && entry.ResourceVersion == current.entry.ResourceVersion) {
		return
	}
	if entry.Invalid != nil {
		klog.Errorf("invalid LDAP cache ConfigMap %q: %v", entry.Name, entry.Invalid)
	}
	d.users[entry.Name] = userCell{entry: entry, deleted: deleted}
}

func (d *UserDirectory) restoreUsers(ctx context.Context) (string, error) {
	list, err := d.store.List(ctx)
	if err != nil {
		return "", err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	present := make(map[string]bool, len(list.Entries))
	for _, entry := range list.Entries {
		present[entry.Name] = true
		d.applyLocked(entry, false)
	}
	for name := range d.users {
		if !present[name] {
			d.applyLocked(cache.UserEntry{Name: name, ResourceVersion: list.ResourceVersion}, true)
		}
	}
	return list.ResourceVersion, nil
}

// Run lists then watches from that list's revision, closing the startup gap.
// Empty caches are ready; LDAP availability is irrelevant to startup.
func (d *UserDirectory) Run(stop <-chan struct{}) error {
	go func() {
		select {
		case <-stop:
			d.cancel()
		case <-d.ctx.Done():
		}
	}()
	version, err := d.restoreUsers(d.ctx)
	if err != nil {
		d.cancel()
		return err
	}
	stream, err := d.store.Watch(d.ctx, version)
	if err != nil {
		d.cancel()
		return err
	}
	d.synced.Store(true)
	go d.synchronize(stream)
	go d.runRefresh()
	return nil
}

func (d *UserDirectory) synchronize(stream watch.Interface) {
	for {
		d.consume(stream)
		stream.Stop()
		if d.ctx.Err() != nil {
			return
		}
		// Relist after interruptions, including expired resource versions. The
		// returned revision establishes a fresh gap-free watch.
		timer := time.NewTimer(time.Second)
		select {
		case <-d.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		version, err := d.restoreUsers(d.ctx)
		if err == nil {
			stream, err = d.store.Watch(d.ctx, version)
		}
		if err != nil {
			klog.Errorf("LDAP cache synchronization: %v", err)
			stream = watch.NewEmptyWatch()
		}
	}
}
func (d *UserDirectory) consume(stream watch.Interface) {
	for {
		select {
		case <-d.ctx.Done():
			return
		case event, ok := <-stream.ResultChan():
			if !ok || event.Type == watch.Error {
				return
			}
			if event.Type == watch.Bookmark {
				continue
			}
			cm, ok := event.Object.(*corev1.ConfigMap)
			if !ok {
				continue
			}
			d.apply(d.store.Decode(cm), event.Type == watch.Deleted)
		}
	}
}

func (d *UserDirectory) HasSynced() bool { return d.synced.Load() }
func (d *UserDirectory) cached(key string) (cache.UserEntry, bool) {
	name, _ := cache.UserConfigMapName(d.scope(), key)
	d.mu.RLock()
	defer d.mu.RUnlock()
	cell, ok := d.users[name]
	return cell.entry, ok && !cell.deleted && cell.entry.Invalid == nil && cell.entry.Record != nil
}

// scope is configured explicitly by the per-user cache constructor.
func (d *UserDirectory) scope() string { return d.resolver.config.Cache.Scope }
