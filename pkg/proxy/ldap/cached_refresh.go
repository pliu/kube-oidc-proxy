// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"errors"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// SetLeaderCheck is configured before Run. With election disabled, this
// replica refreshes its cache independently, protected by optimistic writes.
func (d *UserDirectory) SetLeaderCheck(check func() bool) { d.isLeader = check }

func (d *UserDirectory) runRefresh() {
	ticker := time.NewTicker(d.resolver.config.RefreshInterval.Duration())
	defer ticker.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			if !d.isLeader() {
				continue
			}
			cycle, cancel := context.WithCancel(d.ctx)
			monitorDone := make(chan struct{})
			go func() {
				defer close(monitorDone)
				poll := time.NewTicker(100 * time.Millisecond)
				defer poll.Stop()
				for {
					select {
					case <-cycle.Done():
						return
					case <-poll.C:
						if !d.isLeader() {
							cancel()
							return
						}
					}
				}
			}()
			if err := d.RefreshCached(cycle); err != nil {
				klog.Errorf("LDAP cached-user refresh: %v", err)
			}
			cancel()
			<-monitorDone
		}
	}
}

// RefreshCached snapshots only known users. Each record commits independently;
// a failed user retains its previous entry while other users can advance.
func (d *UserDirectory) RefreshCached(ctx context.Context) error {
	d.mu.RLock()
	keys := make([]string, 0, len(d.users))
	for _, cell := range d.users {
		if !cell.deleted && cell.entry.Record != nil && cell.entry.Invalid == nil {
			keys = append(keys, cell.entry.Record.Username)
		}
	}
	d.mu.RUnlock()
	start := time.Now()
	jobs := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []error
	for i := 0; i < d.resolver.config.LookupConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for key := range jobs {
				if ctx.Err() != nil {
					return
				}
				_, _, err := d.resolve(ctx, key, true)
				if err != nil {
					mu.Lock()
					failures = append(failures, err)
					mu.Unlock()
				}
			}
		}()
	}
send:
	for _, key := range keys {
		select {
		case <-ctx.Done():
			break send
		case jobs <- key:
		}
	}
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		failures = append(failures, ctx.Err())
	}
	refreshDuration.Observe(time.Since(start).Seconds())
	if len(failures) > 0 {
		lastRefreshSuccess.Set(0)
	} else {
		lastRefreshSuccess.Set(1)
	}
	return errors.Join(failures...)
}
