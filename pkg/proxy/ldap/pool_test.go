// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// poolConn is a directory holding alice in the admins group, counting what is
// done to the connection.
type poolConn struct {
	*fakeConn
	binds, closes atomic.Int64
	closing       atomic.Bool

	// block, when set, holds every search until the connection closes.
	block  atomic.Bool
	closed chan struct{}
}

func newPoolConn() *poolConn {
	return &poolConn{
		fakeConn: connWithUsers([]string{"admins"}, map[string][]string{"alice": {"admins"}}),
		closed:   make(chan struct{}),
	}
}

func (c *poolConn) Bind(username, password string) error {
	c.binds.Add(1)
	return c.fakeConn.Bind(username, password)
}

func (c *poolConn) Search(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
	if c.block.Load() {
		<-c.closed
		return nil, errors.New("connection closed")
	}
	return c.fakeConn.Search(req)
}

func (c *poolConn) Close() error {
	if c.closes.Add(1) == 1 {
		close(c.closed)
	}
	return nil
}

func (c *poolConn) IsClosing() bool { return c.closing.Load() }

// pooledBackend is a resolver with one backend pooling up to size connections,
// on a clock the test moves, dialing the connections given in turn.
type pooledBackend struct {
	*resolver
	dials atomic.Int64
	clock atomic.Int64
}

func newPooledBackend(t *testing.T, size int, conns ...*poolConn) *pooledBackend {
	t.Helper()

	d, err := newResolver(testConfig())
	if err != nil {
		t.Fatalf("unexpected error building directory: %s", err)
	}

	p := &pooledBackend{resolver: d}
	b := d.backends[0]
	b.pool = newConnPool("ldap", size)
	b.pool.now = p.now
	b.dial = func(string) (conn, error) {
		i := p.dials.Add(1)
		if int(i) > len(conns) {
			t.Errorf("dial %d, but the test has %d connections", i, len(conns))
			return nil, errors.New("no connection left")
		}
		return conns[i-1], nil
	}
	t.Cleanup(d.close)

	return p
}

func (p *pooledBackend) now() time.Time          { return time.Unix(0, p.clock.Load()) }
func (p *pooledBackend) advance(d time.Duration) { p.clock.Add(int64(d)) }

func (p *pooledBackend) lookup(t *testing.T) {
	t.Helper()

	groups, err := p.searchUser(context.Background(), "alice", false)
	if err != nil {
		t.Fatalf("lookup failed: %s", err)
	}
	if !reflect.DeepEqual(groups, []string{"admins"}) {
		t.Fatalf("expected the admins group, got %v", groups)
	}
}

func TestPooledConnectionIsReused(t *testing.T) {
	c := newPoolConn()
	p := newPooledBackend(t, 2, c)

	for range 3 {
		p.lookup(t)
		p.advance(connMaxIdle / 2)
	}

	if p.dials.Load() != 1 || c.binds.Load() != 1 {
		t.Errorf("expected one dial and bind for three lookups, got %d and %d", p.dials.Load(), c.binds.Load())
	}
	if c.closes.Load() != 0 {
		t.Errorf("pooled connection was closed %d times", c.closes.Load())
	}

	p.close()
	if c.closes.Load() != 1 {
		t.Errorf("closing the pool closed the idle connection %d times", c.closes.Load())
	}
}

func TestFailureOnPooledConnectionIsRetriedOnAFreshOne(t *testing.T) {
	stale, fresh := newPoolConn(), newPoolConn()
	p := newPooledBackend(t, 2, stale, fresh)

	p.lookup(t)
	// The directory dropped the connection without go-ldap noticing.
	stale.searchErr = errors.New("connection reset by peer")
	p.lookup(t)

	if p.dials.Load() != 2 {
		t.Errorf("expected a second dial for the retry, got %d dials", p.dials.Load())
	}
	if stale.closes.Load() != 1 {
		t.Errorf("failed connection was closed %d times", stale.closes.Load())
	}

	// The fresh connection is pooled in place of the failed one.
	p.lookup(t)
	if p.dials.Load() != 2 {
		t.Errorf("expected the fresh connection to be reused, got %d dials", p.dials.Load())
	}
}

func TestFailureOnFreshConnectionIsNotRetriedOrPooled(t *testing.T) {
	first, second := newPoolConn(), newPoolConn()
	first.searchErr = errors.New("insufficient access")
	p := newPooledBackend(t, 2, first, second)

	if _, err := p.searchUser(context.Background(), "alice", false); err == nil {
		t.Fatal("expected the lookup to fail")
	}
	if p.dials.Load() != 1 {
		t.Errorf("a failure on a fresh connection was retried: %d dials", p.dials.Load())
	}
	if first.closes.Load() != 1 {
		t.Errorf("failed connection was closed %d times", first.closes.Load())
	}

	p.lookup(t)
	if p.dials.Load() != 2 {
		t.Errorf("expected the failed connection not to be reused, got %d dials", p.dials.Load())
	}
}

func TestCanceledLookupClosesPooledConnection(t *testing.T) {
	c, next := newPoolConn(), newPoolConn()
	p := newPooledBackend(t, 2, c, next)
	p.lookup(t)

	c.block.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := p.searchUser(ctx, "alice", false); done <- err }()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected the lookup to be canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock the pooled connection")
	}
	if p.dials.Load() != 1 {
		t.Errorf("a canceled lookup was retried: %d dials", p.dials.Load())
	}
	if c.closes.Load() != 1 {
		t.Errorf("canceled connection was closed %d times", c.closes.Load())
	}

	p.lookup(t)
	if p.dials.Load() != 2 {
		t.Errorf("expected the canceled connection not to be reused, got %d dials", p.dials.Load())
	}
}

func TestExpiredConnectionsAreReplaced(t *testing.T) {
	tests := map[string]func(*testing.T, *pooledBackend, *poolConn){
		"idle too long": func(_ *testing.T, p *pooledBackend, _ *poolConn) {
			p.advance(connMaxIdle)
		},
		"open too long": func(t *testing.T, p *pooledBackend, _ *poolConn) {
			// Kept busy, so that only its age retires it.
			expires := p.now().Add(connMaxLifetime)
			for p.now().Add(connMaxIdle / 2).Before(expires) {
				p.advance(connMaxIdle / 2)
				p.lookup(t)
			}
			p.advance(expires.Sub(p.now()))
		},
		"closed by the directory": func(_ *testing.T, _ *pooledBackend, c *poolConn) {
			c.closing.Store(true)
		},
	}

	for name, expire := range tests {
		t.Run(name, func(t *testing.T) {
			old, fresh := newPoolConn(), newPoolConn()
			p := newPooledBackend(t, 2, old, fresh)
			p.lookup(t)

			expire(t, p, old)
			if p.dials.Load() != 1 {
				t.Fatalf("connection replaced before it expired: %d dials", p.dials.Load())
			}

			p.lookup(t)
			if p.dials.Load() != 2 {
				t.Errorf("expected the expired connection to be replaced, got %d dials", p.dials.Load())
			}
			if old.closes.Load() != 1 {
				t.Errorf("expired connection was closed %d times", old.closes.Load())
			}
		})
	}
}

func TestPoolKeepsAtMostItsSizeIdle(t *testing.T) {
	pool := newConnPool("ldap", 2)
	conns := []*poolConn{newPoolConn(), newPoolConn(), newPoolConn()}
	for _, c := range conns {
		pool.put(&pooledConn{conn: c, opened: pool.now()})
	}

	if got := []int64{conns[0].closes.Load(), conns[1].closes.Load(), conns[2].closes.Load()}; !reflect.DeepEqual(got, []int64{0, 0, 1}) {
		t.Errorf("expected only the connection over the size to be closed, got close counts %v", got)
	}

	// The most recently returned is reused first.
	if c := pool.get(); c == nil || c.conn != conn(conns[1]) {
		t.Errorf("expected the most recently used connection")
	}

	pool.close()
	if conns[0].closes.Load() != 1 {
		t.Errorf("closing the pool closed its idle connection %d times", conns[0].closes.Load())
	}
	pool.put(&pooledConn{conn: conns[1], opened: pool.now()})
	if conns[1].closes.Load() != 1 {
		t.Errorf("a connection returned to a closed pool was closed %d times", conns[1].closes.Load())
	}
}

func TestPoolReapsConnectionsBehindBusyConnection(t *testing.T) {
	old, busy := newPoolConn(), newPoolConn()
	p := newPooledBackend(t, 2)
	pool := p.backends[0].pool
	pool.put(&pooledConn{conn: old, opened: p.now()})
	pool.put(&pooledConn{conn: busy, opened: p.now()})
	for range 3 {
		p.advance(connMaxIdle / 2)
		c := pool.get()
		if c == nil || c.conn != busy {
			t.Fatal("expected busy connection to remain reusable")
		}
		pool.put(c)
	}
	pool.reap()
	if old.closes.Load() != 1 || busy.closes.Load() != 0 {
		t.Fatalf("close counts: expired=%d busy=%d", old.closes.Load(), busy.closes.Load())
	}
}

func TestPoolSchedulesExpiryWithoutCheckouts(t *testing.T) {
	for _, expiry := range []string{"idle", "lifetime", "closing"} {
		t.Run(expiry, func(t *testing.T) {
			c := newPoolConn()
			p := newPooledBackend(t, 1)
			pool := p.backends[0].pool
			pool.put(&pooledConn{conn: c, opened: p.now()})
			switch expiry {
			case "idle":
				p.advance(connMaxIdle)
			case "lifetime":
				p.advance(connMaxLifetime)
				pool.mu.Lock()
				pool.idle[0].used = p.now()
				pool.mu.Unlock()
			case "closing":
				c.closing.Store(true)
			}
			// Accelerate the actual scheduled callback without another checkout.
			pool.mu.Lock()
			pool.timer.Reset(time.Millisecond)
			pool.mu.Unlock()
			select {
			case <-c.closed:
			case <-time.After(time.Second):
				t.Fatal("scheduled cleanup did not close expired connection")
			}
			pool.mu.Lock()
			defer pool.mu.Unlock()
			if len(pool.idle) != 0 || pool.timer != nil {
				t.Fatal("empty pool retained connections or scheduled cleanup")
			}
		})
	}
}

func TestPoolCloseStopsScheduledCleanup(t *testing.T) {
	c := newPoolConn()
	pool := newConnPool("ldap", 1)
	pool.put(&pooledConn{conn: c, opened: pool.now()})
	pool.close()
	pool.close()
	pool.reap()
	if c.closes.Load() != 1 || pool.timer != nil {
		t.Fatal("closing pool did not stop cleanup and close connection exactly once")
	}
}

func TestPoolConcurrentCheckoutCleanupAndClose(t *testing.T) {
	pool := newConnPool("ldap", 8)
	conns := make([]*poolConn, 8)
	for i := range conns {
		conns[i] = newPoolConn()
		pool.put(&pooledConn{conn: conns[i], opened: pool.now()})
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		wg.Go(func() {
			<-start
			for range 100 {
				if c := pool.get(); c != nil {
					pool.put(c)
				}
			}
		})
	}
	wg.Go(func() {
		<-start
		for range 100 {
			pool.reap()
		}
	})
	close(start)
	pool.close()
	wg.Wait()
	for _, c := range conns {
		if c.closes.Load() != 1 {
			t.Fatalf("connection closed %d times", c.closes.Load())
		}
	}
}

func TestPoolCountsClosedConnectionsByReason(t *testing.T) {
	tests := map[string]func(t *testing.T, p *pooledBackend, c *poolConn) *poolConn{
		closedIdle: func(_ *testing.T, p *pooledBackend, c *poolConn) *poolConn {
			p.advance(connMaxIdle)
			p.backends[0].pool.reap()
			return c
		},
		closedLifetime: func(t *testing.T, p *pooledBackend, c *poolConn) *poolConn {
			for range 2 * connMaxLifetime / connMaxIdle {
				p.advance(connMaxIdle / 2)
				p.lookup(t)
			}
			return c
		},
		closedByServer: func(_ *testing.T, p *pooledBackend, c *poolConn) *poolConn {
			c.closing.Store(true)
			p.backends[0].pool.reap()
			return c
		},
		closedFailed: func(t *testing.T, p *pooledBackend, c *poolConn) *poolConn {
			c.searchErr = errors.New("insufficient access")
			p.lookup(t) // retried on a fresh connection
			return c
		},
		closedCanceled: func(t *testing.T, p *pooledBackend, c *poolConn) *poolConn {
			c.block.Store(true)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := p.searchUser(ctx, "alice", false); !errors.Is(err, context.Canceled) {
				t.Fatalf("expected the lookup to be canceled, got %v", err)
			}
			return c
		},
		closedPoolFull: func(_ *testing.T, p *pooledBackend, _ *poolConn) *poolConn {
			extra := newPoolConn()
			p.backends[0].pool.put(&pooledConn{conn: extra, opened: p.now(), used: p.now()})
			return extra
		},
		closedShutdown: func(_ *testing.T, p *pooledBackend, c *poolConn) *poolConn {
			p.close()
			return c
		},
	}

	for reason, close := range tests {
		t.Run(reason, func(t *testing.T) {
			c := newPoolConn()
			p := newPooledBackend(t, 1, c, newPoolConn())
			p.lookup(t)

			counters := map[string]float64{}
			for _, r := range []string{closedIdle, closedLifetime, closedByServer, closedFailed, closedCanceled, closedPoolFull, closedShutdown} {
				counters[r] = testutil.ToFloat64(backendConnectionsClosed.WithLabelValues("ldap", r))
			}

			closed := close(t, p, c)

			for r, before := range counters {
				want := before
				if r == reason {
					want++
				}
				if got := testutil.ToFloat64(backendConnectionsClosed.WithLabelValues("ldap", r)); got != want {
					t.Errorf("%s closes: expected %v, got %v", r, want, got)
				}
			}
			if closed.closes.Load() != 1 {
				t.Errorf("connection closed %d times", closed.closes.Load())
			}
		})
	}
}
