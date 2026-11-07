// Copyright Jetstack Ltd. See LICENSE for details.
package integration

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jetstack/kube-oidc-proxy/cmd/app"
	"github.com/jetstack/kube-oidc-proxy/pkg/util"
	"github.com/jetstack/kube-oidc-proxy/test/tools/issuer/pkg/issuer"
	testutil "github.com/jetstack/kube-oidc-proxy/test/util"
)

func testCertificates(t *testing.T, dir string) (*testutil.KeyBundle, string, string) {
	t.Helper()
	bundle, err := testutil.NewTLSSelfSignedCertKey("127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return bundle, writeFile(t, dir, "tls.crt", bundle.CertBytes), writeFile(t, dir, "tls.key", bundle.KeyBytes)
}

func componentStop(t *testing.T) <-chan struct{} {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	return stop
}

type testProxyConfig struct {
	apiURL          string
	certPath        string
	keyPath         string
	authnConfigPath string
	ca              []byte
	extraArgs       []string
}

type testProxy struct {
	url    string
	client *http.Client
	stop   func()
}

func startTestProxy(t *testing.T, config testProxyConfig) *testProxy {
	t.Helper()
	port, readinessPort := freePort(t), freePort(t)
	stop := make(chan struct{})
	command := app.NewRunCommand(stop)
	command.SetArgs(append([]string{
		"--server=" + config.apiURL,
		"--bind-address=127.0.0.1",
		"--secure-port=" + port,
		"--tls-cert-file=" + config.certPath,
		"--tls-private-key-file=" + config.keyPath,
		"--readiness-probe-port=" + readinessPort,
		"--oidc-config-file=" + config.authnConfigPath,
		"--leader-elect-resource-namespace=proxy",
	}, config.extraArgs...))
	commandErr := make(chan error, 1)
	go func() { commandErr <- command.Execute() }()
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			close(stop)
			select {
			case err := <-commandErr:
				if err != nil {
					t.Errorf("proxy stopped with an error: %s", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("proxy did not stop within 10s")
			}
		})
	}
	t.Cleanup(shutdown)
	waitForReady(t, "http://127.0.0.1:"+readinessPort+"/ready", commandErr)
	waitForLeader(t, config.apiURL)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(config.ca) {
		t.Fatal("failed to trust proxy certificate")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	t.Cleanup(transport.CloseIdleConnections)
	return &testProxy{url: "https://127.0.0.1:" + port,
		client: &http.Client{Timeout: 5 * time.Second, Transport: transport}, stop: shutdown}
}

type testIssuer struct {
	url    string
	ca     []byte
	signer *testutil.KeyBundle
}

// startIssuer serves an OIDC issuer over TLS whose tokens are signed by a key
// of its own.
func startIssuer(t *testing.T, dir, name string, stopCh <-chan struct{}) *testIssuer {
	t.Helper()

	signer, err := testutil.NewTLSSelfSignedCertKey("127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil)
	if err != nil {
		t.Fatalf("failed to create signing key for issuer %s: %s", name, err)
	}

	server := httptest.NewUnstartedServer(nil)
	url := "https://" + server.Listener.Addr().String()
	handler, err := issuer.New(url,
		writeFile(t, dir, name+"-signer.key", signer.KeyBytes),
		writeFile(t, dir, name+"-signer.crt", signer.CertBytes),
		stopCh)
	if err != nil {
		t.Fatalf("failed to create mock OIDC issuer %s: %s", name, err)
	}
	server.Config.Handler = handler
	server.StartTLS()
	t.Cleanup(server.Close)

	return &testIssuer{
		url:    url,
		ca:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
		signer: signer,
	}
}

// indent prefixes every line of a PEM bundle so it nests in a YAML block
// scalar.
func indent(pemBytes []byte, prefix string) string {
	return prefix + strings.ReplaceAll(strings.TrimSpace(string(pemBytes)), "\n", "\n"+prefix)
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("failed to write %s: %s", name, err)
	}
	return path
}

func freePort(t *testing.T) string {
	t.Helper()
	port, err := util.FreePort()
	if err != nil {
		t.Fatalf("failed to find a free port: %s", err)
	}
	return port
}

func waitForReady(t *testing.T, readyURL string, commandErr chan error) {
	t.Helper()

	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-commandErr:
			// Leave the result available for the shutdown cleanup.
			commandErr <- err
			t.Fatalf("proxy exited before becoming ready: %v", err)
		default:
		}

		response, err := client.Get(readyURL)
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}

		time.Sleep(25 * time.Millisecond)
	}

	t.Fatalf("proxy did not become ready at %s within 15s", readyURL)
}
