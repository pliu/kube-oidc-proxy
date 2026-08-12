// Copyright Jetstack Ltd. See LICENSE for details.
package cache

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func testSecretStore(t *testing.T, objects ...runtime.Object) (*Secret, *fake.Clientset) {
	t.Helper()

	client := fake.NewSimpleClientset(objects...)

	store, err := NewSecret(client, "kube-oidc-proxy", "ad-mapping", "mapping.json.gz")
	if err != nil {
		t.Fatalf("unexpected error building store: %s", err)
	}

	return store, client
}

func TestSecretRoundTrips(t *testing.T) {
	store, client := testSecretStore(t)

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

	// The Secret must have been created rather than the save failing.
	secret, err := client.CoreV1().Secrets("kube-oidc-proxy").Get(
		context.Background(), "ad-mapping", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("unexpected error getting the Secret: %s", err)
	}

	if got := secret.Labels[managedByLabel]; got != managedByValue {
		t.Errorf("expected the Secret to be labelled as managed by %q, got %q", managedByValue, got)
	}

	// A mapping of any size compresses, and the API server caps a Secret at
	// 1MiB, so what lands in the Secret must be compressed.
	stored := secret.Data["mapping.json.gz"]
	if len(stored) < 2 || stored[0] != 0x1f || stored[1] != 0x8b {
		t.Errorf("expected the persisted mapping to be gzipped, got %q", stored)
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

// The proxy must not stamp on the other keys of a Secret it shares.
func TestSecretSaveKeepsOtherKeys(t *testing.T) {
	store, client := testSecretStore(t, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ad-mapping", Namespace: "kube-oidc-proxy"},
		Data:       map[string][]byte{"unrelated": []byte("keep me")},
	})

	if err := store.Save(context.Background(), []byte("mapping")); err != nil {
		t.Fatalf("unexpected error saving: %s", err)
	}

	secret, err := client.CoreV1().Secrets("kube-oidc-proxy").Get(
		context.Background(), "ad-mapping", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("unexpected error getting the Secret: %s", err)
	}

	if got := string(secret.Data["unrelated"]); got != "keep me" {
		t.Errorf("expected the unrelated key to be kept, got %q", got)
	}
}

func TestSecretLoadTreatsAMissingKeyAsNothingPersisted(t *testing.T) {
	store, _ := testSecretStore(t, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ad-mapping", Namespace: "kube-oidc-proxy"},
		Data:       map[string][]byte{"unrelated": []byte("keep me")},
	})

	if _, err := store.Load(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// A Secret written by hand is a reasonable way to seed the mapping, and is not
// going to be gzipped.
func TestSecretLoadToleratesAnUncompressedPayload(t *testing.T) {
	store, _ := testSecretStore(t, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ad-mapping", Namespace: "kube-oidc-proxy"},
		Data:       map[string][]byte{"mapping.json.gz": []byte(`{"version":1}`)},
	})

	data, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("unexpected error loading: %s", err)
	}

	if string(data) != `{"version":1}` {
		t.Errorf("expected the payload to be read as is, got %q", data)
	}
}

// Two replicas refresh on their own schedules and write the same Secret, so a
// conflict is expected rather than exceptional.
func TestSecretSaveRetriesOnConflict(t *testing.T) {
	store, client := testSecretStore(t, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ad-mapping", Namespace: "kube-oidc-proxy"},
	})

	var updates int
	client.PrependReactor("update", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updates++
		if updates == 1 {
			return true, nil, apierrors.NewConflict(
				corev1.Resource("secrets"), "ad-mapping", errors.New("the object has been modified"))
		}

		return false, nil, nil
	})

	if err := store.Save(context.Background(), []byte("mapping")); err != nil {
		t.Fatalf("expected the conflicting save to be retried, got %s", err)
	}

	if updates != 2 {
		t.Errorf("expected 2 update attempts, got %d", updates)
	}

	data, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("unexpected error loading: %s", err)
	}
	if string(data) != "mapping" {
		t.Errorf("expected the retried save to have landed, got %q", data)
	}
}

// Losing the race to create the Secret must resolve into an update, not an
// error that loses the mapping.
func TestSecretSaveHandlesALostCreateRace(t *testing.T) {
	store, client := testSecretStore(t)

	var creates int
	client.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		creates++
		if creates == 1 {
			// Another replica got there first, and the object now exists. The
			// tracker is written directly: going back through the client here
			// would deadlock against the lock the reactor is running under.
			if err := client.Tracker().Add(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Name: "ad-mapping", Namespace: "kube-oidc-proxy"}}); err != nil {
				return true, nil, err
			}

			return true, nil, apierrors.NewAlreadyExists(corev1.Resource("secrets"), "ad-mapping")
		}

		return false, nil, nil
	})

	if err := store.Save(context.Background(), []byte("mapping")); err != nil {
		t.Fatalf("expected the lost create race to be retried as an update, got %s", err)
	}

	data, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("unexpected error loading: %s", err)
	}
	if string(data) != "mapping" {
		t.Errorf("expected the mapping to have landed, got %q", data)
	}
}

// Exceeding the limit fails the write, so it is worth an error that says what
// to do about it rather than one from the API server.
func TestSecretSaveRejectsAnOversizedMapping(t *testing.T) {
	store, _ := testSecretStore(t)

	// Random, and so incompressible, so that the size check is actually
	// reached rather than gzip shrinking the payload under the limit.
	oversized := make([]byte, maxSecretSize*2)
	if _, err := rand.New(rand.NewSource(1)).Read(oversized); err != nil {
		t.Fatalf("unexpected error building an oversized mapping: %s", err)
	}

	err := store.Save(context.Background(), oversized)
	if err == nil {
		t.Fatal("expected an error saving an oversized mapping")
	}

	if !strings.Contains(err.Error(), "persist to a file instead") {
		t.Errorf("expected the error to suggest a way out, got %q", err)
	}
}

func TestNewSecretValidatesItsArguments(t *testing.T) {
	client := fake.NewSimpleClientset()

	tests := map[string]struct {
		client               *fake.Clientset
		namespace, name, key string
		expErr               string
	}{
		"no client": {nil, "kube-oidc-proxy", "ad-mapping", "mapping.json.gz", "no Kubernetes client"},
		"no name":   {client, "kube-oidc-proxy", "", "mapping.json.gz", "no name configured"},
		"no key":    {client, "kube-oidc-proxy", "ad-mapping", "", "no key configured"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// A nil *fake.Clientset in an interface is not a nil interface, so
			// pass the untyped nil the caller would.
			var err error
			if test.client == nil {
				_, err = NewSecret(nil, test.namespace, test.name, test.key)
			} else {
				_, err = NewSecret(test.client, test.namespace, test.name, test.key)
			}

			if err == nil {
				t.Fatalf("expected an error containing %q, got none", test.expErr)
			}

			if !strings.Contains(err.Error(), test.expErr) {
				t.Errorf("expected an error containing %q, got %q", test.expErr, err)
			}
		})
	}
}

// Running in cluster, the namespace of the Secret can be worked out rather
// than configured.
func TestNewSecretDefaultsTheNamespace(t *testing.T) {
	t.Setenv(namespaceEnvVar, "from-the-environment")

	store, err := NewSecret(fake.NewSimpleClientset(), "", "ad-mapping", "mapping.json.gz")
	if err != nil {
		t.Fatalf("unexpected error building store: %s", err)
	}

	if store.namespace != "from-the-environment" {
		t.Errorf("expected the namespace to be taken from $%s, got %q", namespaceEnvVar, store.namespace)
	}

	if !strings.Contains(store.String(), "from-the-environment/ad-mapping") {
		t.Errorf("expected the store to describe itself, got %q", store.String())
	}
}

func TestCompressRoundTrips(t *testing.T) {
	data := bytes.Repeat([]byte(`{"users":{"alice@example.net":["admins"]}}`), 100)

	compressed, err := compress(data)
	if err != nil {
		t.Fatalf("unexpected error compressing: %s", err)
	}

	if len(compressed) >= len(data) {
		t.Errorf("expected the mapping to compress, got %d bytes from %d", len(compressed), len(data))
	}

	decompressed, err := decompress(compressed)
	if err != nil {
		t.Fatalf("unexpected error decompressing: %s", err)
	}

	if !bytes.Equal(decompressed, data) {
		t.Error("expected the mapping to survive a round trip")
	}
}
