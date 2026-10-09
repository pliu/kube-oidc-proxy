// Copyright Jetstack Ltd. See LICENSE for details.

// ldap-loadgen drives the LDAP e2e test from inside the cluster. It logs every
// directory user in to Keycloak, sends each one's first request through the
// proxy, waits for the leader to refresh them all, then measures requests
// served from the cache against the same requests sent straight to the API
// server. It checks that membership decides access, and prints a latency
// report built from its own timings and from the proxy's metrics.
//
// It runs in the cluster so that neither Keycloak nor the proxy has to be
// reachable from the host, and so that the timings carry no port-forward.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"k8s.io/client-go/rest"
)

type options struct {
	tokenURL, clientID, password string
	userPrefix, outsider         string
	users                        int
	caFiles                      string
	proxyURL, metricsURL         string
	namespace                    string
	tokenConcurrency             int
	coldConcurrency              int
	warmConcurrency              int
	warmRequests                 int
	refreshTimeout               time.Duration
	groups, groupsPerUser        int
	proxyKubeClient              string
}

const (
	overheadMetric    = "kube_oidc_proxy_request_overhead_seconds"
	userRefreshMetric = "kube_oidc_proxy_ldap_backend_refresh_duration_seconds"
	fullRefreshMetric = "kube_oidc_proxy_ldap_full_refresh_duration_seconds"
	failuresMetric    = "kube_oidc_proxy_ldap_user_refresh_failures_total"
	requestsMetric    = "kube_oidc_proxy_requests_total"
)

func main() {
	var o options
	flag.StringVar(&o.tokenURL, "token-url", "", "Keycloak token endpoint")
	flag.StringVar(&o.clientID, "client-id", "", "Keycloak client")
	flag.StringVar(&o.password, "password", "", "password of every directory user")
	flag.StringVar(&o.userPrefix, "user-prefix", "user", "directory users are <prefix>0001 and on")
	flag.StringVar(&o.outsider, "outsider", "", "a directory user in no group RBAC grants anything")
	flag.IntVar(&o.users, "users", 1000, "number of directory users")
	flag.IntVar(&o.groups, "groups", 0, "number of directory groups, for the report")
	flag.IntVar(&o.groupsPerUser, "groups-per-user", 0, "groups each user holds, for the report")
	flag.StringVar(&o.proxyKubeClient, "proxy-kube-client", "", "the proxy's Kubernetes client limits, for the report")
	flag.StringVar(&o.caFiles, "ca-files", "", "comma separated PEM files trusted for Keycloak and the proxy")
	flag.StringVar(&o.proxyURL, "proxy-url", "", "kube-oidc-proxy URL")
	flag.StringVar(&o.metricsURL, "metrics-url", "", "kube-oidc-proxy metrics URL")
	flag.StringVar(&o.namespace, "namespace", "", "namespace whose pods are listed")
	flag.IntVar(&o.tokenConcurrency, "token-concurrency", 8, "concurrent Keycloak logins")
	flag.IntVar(&o.coldConcurrency, "cold-concurrency", 4, "concurrent first requests; keep at or below the proxy's lookupConcurrency")
	flag.IntVar(&o.warmConcurrency, "warm-concurrency", 8, "concurrent cached and direct requests")
	flag.IntVar(&o.warmRequests, "warm-requests", 5000, "cached and direct requests sent")
	flag.DurationVar(&o.refreshTimeout, "refresh-timeout", 20*time.Minute, "how long to wait for the leader's refresh")
	flag.Parse()

	if err := run(context.Background(), o); err != nil {
		fmt.Fprintf(os.Stderr, "ldap-loadgen: %s\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, o options) error {
	pool, err := certPool(strings.Split(o.caFiles, ","))
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: time.Minute,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{RootCAs: pool},
			MaxIdleConnsPerHost: 64,
		},
	}

	users := make([]string, o.users)
	for i := range users {
		users[i] = fmt.Sprintf("%s%04d", o.userPrefix, i+1)
	}
	podsPath := fmt.Sprintf("/api/v1/namespaces/%s/pods?limit=1", o.namespace)

	r := &report{options: o}

	logf("logging %d users and %q in to Keycloak", len(users), o.outsider)
	tokens, tokenTimes, err := login(ctx, client, o, append([]string{o.outsider}, users...))
	if err != nil {
		return err
	}
	r.add("Keycloak login", "client", tokenTimes)

	// The outsider goes first, so that the first requests measured below are
	// not also the proxy's first requests to the directory.
	logf("checking that %q, in no granted group, is forbidden", o.outsider)
	if code, _, err := get(ctx, client, o.proxyURL+podsPath, tokens[o.outsider]); err != nil || code != http.StatusForbidden {
		return fmt.Errorf("expected %q to be forbidden, got %d: %v", o.outsider, code, err)
	}

	before, err := scrape(ctx, client, o.metricsURL)
	if err != nil {
		return err
	}

	logf("sending each user's first request, %d at a time", o.coldConcurrency)
	cold, err := load(ctx, client, o.proxyURL+podsPath, o.coldConcurrency, len(users), func(i int) string { return tokens[users[i]] })
	if err != nil {
		return fmt.Errorf("first requests: %w", err)
	}
	afterCold, err := scrape(ctx, client, o.metricsURL)
	if err != nil {
		return err
	}
	r.add("First request (LDAP lookup)", "client via proxy", cold)
	r.addHistogram("First request (LDAP lookup)", "proxy overhead", afterCold.histogram(overheadMetric, nil).sub(before.histogram(overheadMetric, nil)))
	r.addHistogram("First request (LDAP lookup)", "LDAP lookup per user and backend",
		afterCold.histogram(userRefreshMetric, map[string]string{"trigger": "realtime"}).sub(before.histogram(userRefreshMetric, map[string]string{"trigger": "realtime"})))

	cycle, err := waitForFullRefresh(ctx, client, o, afterCold)
	if err != nil {
		return err
	}
	r.addHistogram("Leader refresh of all users", "full cycle", cycle.full)
	r.addHistogram("Leader refresh of all users", "LDAP lookup per user and backend", cycle.perUser)

	rng := rand.New(rand.NewSource(1))
	picks := make([]string, o.warmRequests)
	for i := range picks {
		picks[i] = users[rng.Intn(len(users))]
	}

	warmBefore, err := scrape(ctx, client, o.metricsURL)
	if err != nil {
		return err
	}
	logf("sending %d requests from cached users, %d at a time", o.warmRequests, o.warmConcurrency)
	warm, err := load(ctx, client, o.proxyURL+podsPath, o.warmConcurrency, len(picks), func(i int) string { return tokens[picks[i]] })
	if err != nil {
		return fmt.Errorf("cached requests: %w", err)
	}
	warmAfter, err := scrape(ctx, client, o.metricsURL)
	if err != nil {
		return err
	}
	r.add("Cached user", "client via proxy", warm)
	r.addHistogram("Cached user", "proxy overhead", warmAfter.histogram(overheadMetric, nil).sub(warmBefore.histogram(overheadMetric, nil)))

	logf("sending %d requests straight to the API server, %d at a time", o.warmRequests, o.warmConcurrency)
	direct, err := loadDirect(ctx, podsPath, o.warmConcurrency, o.warmRequests)
	if err != nil {
		return fmt.Errorf("direct requests: %w", err)
	}
	r.add("Straight to the API server", "client", direct)

	r.failures = map[string]float64{
		"ldap":       warmAfter.counter(failuresMetric, map[string]string{"source": "ldap"}),
		"kubernetes": warmAfter.counter(failuresMetric, map[string]string{"source": "kubernetes"}),
	}
	r.codes = warmAfter.counters(requestsMetric, "code")

	r.print(os.Stdout)

	if n := r.failures["ldap"] + r.failures["kubernetes"]; n > 0 {
		return fmt.Errorf("%v user refreshes failed", n)
	}
	return nil
}

// login fetches an ID token for every user with the password grant.
func login(ctx context.Context, client *http.Client, o options, users []string) (map[string]string, []time.Duration, error) {
	tokens := make(map[string]string, len(users))
	times := make([]time.Duration, len(users))
	var mu sync.Mutex

	err := parallel(o.tokenConcurrency, len(users), func(i int) error {
		form := url.Values{
			"grant_type": {"password"},
			"client_id":  {o.clientID},
			"username":   {users[i]},
			"password":   {o.password},
			"scope":      {"openid"},
		}

		var lastErr error
		for range 5 {
			start := time.Now()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.tokenURL, strings.NewReader(form.Encode()))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := client.Do(req)
			if err != nil {
				lastErr = err
				time.Sleep(time.Second)
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				lastErr = fmt.Errorf("login of %q: %s: %s", users[i], resp.Status, body)
				time.Sleep(time.Second)
				continue
			}
			var token struct {
				IDToken string `json:"id_token"`
			}
			if err := json.Unmarshal(body, &token); err != nil || token.IDToken == "" {
				return fmt.Errorf("login of %q returned no id_token: %v", users[i], err)
			}
			times[i] = time.Since(start)
			mu.Lock()
			tokens[users[i]] = token.IDToken
			mu.Unlock()
			return nil
		}
		return lastErr
	})

	return tokens, times, err
}

// load sends n GETs of target, concurrency at a time, with the token of each,
// and requires every one to succeed.
func load(ctx context.Context, client *http.Client, target string, concurrency, n int, token func(int) string) ([]time.Duration, error) {
	times := make([]time.Duration, n)
	err := parallel(concurrency, n, func(i int) error {
		code, took, err := get(ctx, client, target, token(i))
		if err != nil {
			return err
		}
		if code != http.StatusOK {
			return fmt.Errorf("request %d: got %d", i, code)
		}
		times[i] = took
		return nil
	})
	return times, err
}

// loadDirect sends the same requests to the API server, as this pod's own
// service account.
func loadDirect(ctx context.Context, path string, concurrency, n int) ([]time.Duration, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	rt, err := rest.TransportFor(config)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: rt, Timeout: time.Minute}
	return load(ctx, client, config.Host+path, concurrency, n, func(int) string { return "" })
}

func get(ctx context.Context, client *http.Client, target, token string) (int, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, 0, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, time.Since(start), nil
}

func parallel(concurrency, n int, fn func(int) error) error {
	jobs := make(chan int)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range concurrency {
		wg.Go(func() {
			for i := range jobs {
				if err := fn(i); err != nil {
					errs <- err
				}
			}
		})
	}
	for i := range n {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	close(errs)

	var all []error
	for err := range errs {
		all = append(all, err)
	}
	if len(all) > 0 {
		return fmt.Errorf("%d of %d failed, first: %w", len(all), n, all[0])
	}
	return nil
}

type refreshCycle struct {
	full, perUser histogram
}

// waitForFullRefresh returns the second refresh cycle to complete after every
// user was cached. The first may have started, and taken its snapshot of
// cached users, before the last of them arrived; the second cannot have.
func waitForFullRefresh(ctx context.Context, client *http.Client, o options, after *metrics) (*refreshCycle, error) {
	logf("waiting for the leader to refresh every cached user")
	deadline := time.Now().Add(o.refreshTimeout)
	start := after.histogram(fullRefreshMetric, nil).count
	asyncLabels := map[string]string{"trigger": "async"}

	var first *metrics
	for time.Now().Before(deadline) {
		m, err := scrape(ctx, client, o.metricsURL)
		if err != nil {
			return nil, err
		}
		switch done := m.histogram(fullRefreshMetric, nil).count - start; {
		case done >= 2 && first != nil:
			return &refreshCycle{
				full:    m.histogram(fullRefreshMetric, nil).sub(first.histogram(fullRefreshMetric, nil)),
				perUser: m.histogram(userRefreshMetric, asyncLabels).sub(first.histogram(userRefreshMetric, asyncLabels)),
			}, nil
		case done >= 2:
			return nil, errors.New("two refresh cycles completed between scrapes; lower the scrape interval")
		case done == 1 && first == nil:
			first = m
		}
		time.Sleep(250 * time.Millisecond)
	}
	return nil, fmt.Errorf("no complete refresh cycle within %s", o.refreshTimeout)
}

// metrics is one scrape of the proxy.
type metrics map[string]*dto.MetricFamily

func scrape(ctx context.Context, client *http.Client, target string) (*metrics, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scrape: %w", err)
	}
	defer resp.Body.Close()
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("scrape: %w", err)
	}
	m := metrics(families)
	return &m, nil
}

func matches(metric *dto.Metric, labels map[string]string) bool {
	for name, value := range labels {
		found := false
		for _, l := range metric.GetLabel() {
			if l.GetName() == name && l.GetValue() == value {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// histogram sums the series of a histogram whose labels match.
func (m *metrics) histogram(name string, labels map[string]string) histogram {
	h := histogram{buckets: map[float64]float64{}}
	family := (*m)[name]
	if family == nil {
		return h
	}
	for _, metric := range family.GetMetric() {
		if !matches(metric, labels) {
			continue
		}
		hist := metric.GetHistogram()
		h.count += float64(hist.GetSampleCount())
		h.sum += hist.GetSampleSum()
		for _, b := range hist.GetBucket() {
			h.buckets[b.GetUpperBound()] += float64(b.GetCumulativeCount())
		}
	}
	return h
}

func (m *metrics) counter(name string, labels map[string]string) float64 {
	var total float64
	if family := (*m)[name]; family != nil {
		for _, metric := range family.GetMetric() {
			if matches(metric, labels) {
				total += metric.GetCounter().GetValue()
			}
		}
	}
	return total
}

func (m *metrics) counters(name, label string) map[string]float64 {
	out := map[string]float64{}
	if family := (*m)[name]; family != nil {
		for _, metric := range family.GetMetric() {
			for _, l := range metric.GetLabel() {
				if l.GetName() == label {
					out[l.GetValue()] += metric.GetCounter().GetValue()
				}
			}
		}
	}
	return out
}

type histogram struct {
	count, sum float64
	buckets    map[float64]float64 // cumulative counts by upper bound
}

func (h histogram) sub(o histogram) histogram {
	d := histogram{count: h.count - o.count, sum: h.sum - o.sum, buckets: map[float64]float64{}}
	for le, c := range h.buckets {
		d.buckets[le] = c - o.buckets[le]
	}
	return d
}

// quantile estimates a quantile as Prometheus' histogram_quantile does, by
// interpolating linearly within the bucket the quantile falls in.
func (h histogram) quantile(q float64) float64 {
	if h.count == 0 {
		return math.NaN()
	}
	bounds := make([]float64, 0, len(h.buckets))
	for le := range h.buckets {
		bounds = append(bounds, le)
	}
	sort.Float64s(bounds)
	rank := q * h.count
	lower, below := 0.0, 0.0
	for _, le := range bounds {
		c := h.buckets[le]
		if c >= rank {
			if math.IsInf(le, 1) {
				return lower
			}
			if c == below {
				return le
			}
			return lower + (le-lower)*(rank-below)/(c-below)
		}
		lower, below = le, c
	}
	return lower
}

type row struct {
	phase, source string
	n             int
	mean, p50     time.Duration
	p90, p99, max time.Duration
	estimated     bool
}

type report struct {
	options
	rows     []row
	failures map[string]float64
	codes    map[string]float64
}

func (r *report) add(phase, source string, samples []time.Duration) {
	sorted := append([]time.Duration(nil), samples...)
	slices.Sort(sorted)
	var total time.Duration
	for _, s := range sorted {
		total += s
	}
	at := func(q float64) time.Duration {
		return sorted[int(math.Ceil(q*float64(len(sorted))))-1]
	}
	r.rows = append(r.rows, row{
		phase: phase, source: source, n: len(sorted),
		mean: total / time.Duration(len(sorted)),
		p50:  at(0.5), p90: at(0.9), p99: at(0.99), max: sorted[len(sorted)-1],
	})
}

func (r *report) addHistogram(phase, source string, h histogram) {
	seconds := func(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }
	row := row{phase: phase, source: source, n: int(h.count), estimated: true}
	if h.count == 1 {
		// One sample: its value is the mean, and bucket percentiles of it
		// would only describe the bucket.
		d := seconds(h.sum)
		row.mean, row.p50, row.p90, row.p99 = d, d, d, d
	} else if h.count > 0 {
		row.mean = seconds(h.sum / h.count)
		row.p50, row.p90, row.p99 = seconds(h.quantile(0.5)), seconds(h.quantile(0.9)), seconds(h.quantile(0.99))
	}
	r.rows = append(r.rows, row)
}

func (r *report) print(out io.Writer) {
	fmt.Fprintln(out, "===== LDAP latency report =====")
	fmt.Fprintf(out, "%d directory users, %d groups, %d groups per user; one proxy replica, one OpenLDAP backend over LDAPS\n",
		r.users, r.groups, r.groupsPerUser)
	fmt.Fprintf(out, "proxy Kubernetes client: %s\n", r.proxyKubeClient)
	fmt.Fprintf(out, "first requests %d at a time; cached and direct requests: %d, %d at a time\n\n",
		r.coldConcurrency, r.warmRequests, r.warmConcurrency)

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(w, "phase\tmeasured\tn\tmean\tp50\tp90\tp99\tmax\t")
	ms := func(d time.Duration) string { return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond)) }
	for _, row := range r.rows {
		max := ms(row.max)
		source := row.source
		if row.estimated {
			max = "-"
			source += " *"
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t\n", row.phase, source, row.n,
			ms(row.mean), ms(row.p50), ms(row.p90), ms(row.p99), max)
	}
	w.Flush()

	fmt.Fprintln(out, "\n* from the proxy's histograms: percentiles are interpolated within buckets, so are estimates")
	fmt.Fprintln(out, "  proxy overhead is the time from a request reaching the proxy to its being forwarded")
	fmt.Fprintf(out, "user refresh failures: ldap=%v kubernetes=%v\n", r.failures["ldap"], r.failures["kubernetes"])
	codes := make([]string, 0, len(r.codes))
	for code, n := range r.codes {
		codes = append(codes, fmt.Sprintf("%s=%v", code, n))
	}
	sort.Strings(codes)
	fmt.Fprintf(out, "proxy responses by code: %s\n", strings.Join(codes, " "))
	fmt.Fprintln(out, "===== end of report =====")
}

func certPool(files []string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, f := range files {
		if f == "" {
			continue
		}
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", f)
		}
	}
	return pool, nil
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s "+format+"\n", append([]any{time.Now().Format(time.TimeOnly)}, args...)...)
}
