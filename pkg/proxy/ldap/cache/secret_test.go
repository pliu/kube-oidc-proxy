// Copyright Jetstack Ltd. See LICENSE for details.
package cache

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
	k8stesting "k8s.io/client-go/testing"
)

func testSecretStore(t *testing.T, objects ...runtime.Object) (*Secret, *fake.Clientset) {
	t.Helper()

	client := fake.NewSimpleClientset(objects...)

	store, err := NewSecret(client, testMetadataClient(objects...),
		"kube-oidc-proxy", "ldap-mapping", "mapping.json.gz")
	if err != nil {
		t.Fatalf("unexpected error building store: %s", err)
	}

	return store, client
}

// testMetadataClient gives the metadata only view of the same objects. The two
// clients are separate fakes, so a write through one is not seen by the other:
// a test of what the metadata view reports seeds it here rather than saving
// through the store first.
func testMetadataClient(objects ...runtime.Object) *metadatafake.FakeMetadataClient {
	scheme := metadatafake.NewTestScheme()
	if err := metav1.AddMetaToScheme(scheme); err != nil {
		panic(err)
	}

	partial := make([]runtime.Object, 0, len(objects))
	for _, object := range objects {
		secret, ok := object.(*corev1.Secret)
		if !ok {
			continue
		}

		partial = append(partial, &metav1.PartialObjectMetadata{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
			ObjectMeta: *secret.ObjectMeta.DeepCopy(),
		})
	}

	return metadatafake.NewSimpleMetadataClient(scheme, partial...)
}

func TestSecretRoundTrips(t *testing.T) {
	store, client := testSecretStore(t)

	// Nothing has been persisted yet, which is the ordinary first start.
	if _, err := store.Load(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	if err := store.Save(context.Background(), []byte("first"), ""); err != nil {
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
		context.Background(), "ldap-mapping", metav1.GetOptions{})
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

	if err := store.Save(context.Background(), []byte("second"), ""); err != nil {
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

// The fingerprint has to reach the object, since it is the only thing a proxy
// serving this mapping has to go on when deciding whether to fetch it again.
func TestSecretSaveStampsTheFingerprint(t *testing.T) {
	store, client := testSecretStore(t)

	if err := store.Save(context.Background(), []byte("first"), "fingerprint-one"); err != nil {
		t.Fatalf("unexpected error saving: %s", err)
	}

	secret, err := client.CoreV1().Secrets("kube-oidc-proxy").Get(
		context.Background(), "ldap-mapping", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("unexpected error getting the Secret: %s", err)
	}

	if got := secret.Annotations[fingerprintAnnotation]; got != "fingerprint-one" {
		t.Errorf("expected the created Secret to carry the fingerprint, got %q", got)
	}

	// And on the update path, where the annotation has to be replaced rather
	// than left describing the mapping that was there before.
	if err := store.Save(context.Background(), []byte("second"), "fingerprint-two"); err != nil {
		t.Fatalf("unexpected error saving: %s", err)
	}

	secret, err = client.CoreV1().Secrets("kube-oidc-proxy").Get(
		context.Background(), "ldap-mapping", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("unexpected error getting the Secret: %s", err)
	}

	if got := secret.Annotations[fingerprintAnnotation]; got != "fingerprint-two" {
		t.Errorf("expected the updated Secret to carry the new fingerprint, got %q", got)
	}
}

// Reading the fingerprint must not read the mapping with it: this runs on
// every poll of every proxy serving the mapping, and the whole point of it is
// that it does not move a megabyte to answer "no change".
func TestSecretFingerprint(t *testing.T) {
	held := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "ldap-mapping",
			Namespace:   "kube-oidc-proxy",
			Annotations: map[string]string{fingerprintAnnotation: "fingerprint-one"},
		},
		Data: map[string][]byte{"mapping.json.gz": []byte("mapping")},
	}

	store, client := testSecretStore(t, held)

	fingerprint, err := store.Fingerprint(context.Background())
	if err != nil {
		t.Fatalf("unexpected error reading the fingerprint: %s", err)
	}
	if fingerprint != "fingerprint-one" {
		t.Errorf("expected the fingerprint of the Secret, got %q", fingerprint)
	}

	// Nothing may have been asked of the client that holds the data.
	for _, action := range client.Actions() {
		t.Errorf("expected the fingerprint to be read from metadata alone, got a %s of %s",
			action.GetVerb(), action.GetResource().Resource)
	}

	// A Secret somebody else made, with no mapping of ours in it, is nothing to
	// serve and nothing to fetch.
	unstamped, _ := testSecretStore(t, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ldap-mapping", Namespace: "kube-oidc-proxy"},
	})

	if _, err := unstamped.Fingerprint(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for a Secret carrying no fingerprint, got %v", err)
	}

	// And neither is a Secret that does not exist at all, which is the ordinary
	// state before the builder has finished its first sweep.
	missing, _ := testSecretStore(t)

	if _, err := missing.Fingerprint(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for a Secret that does not exist, got %v", err)
	}
}

// What a reader is built on: the builder publishes, and the proxies serving
// the mapping are told, rather than finding out when they next look.
func TestSecretWatchReportsPublishedMappings(t *testing.T) {
	held := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "ldap-mapping",
			Namespace:   "kube-oidc-proxy",
			Annotations: map[string]string{fingerprintAnnotation: "fingerprint-one"},
		},
		Data: map[string][]byte{"mapping.json.gz": []byte("mapping")},
	}

	meta := testMetadataClient(held)

	store, err := NewSecret(fake.NewSimpleClientset(held), meta,
		"kube-oidc-proxy", "ldap-mapping", "mapping.json.gz")
	if err != nil {
		t.Fatalf("unexpected error building store: %s", err)
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	changes := make(chan string, 8)
	if err := store.Watch(stopCh, func(fingerprint string) { changes <- fingerprint }); err != nil {
		t.Fatalf("unexpected error watching: %s", err)
	}

	// What is already published arrives first, so a reader that starts after
	// the builder is not left waiting for the next change to happen.
	select {
	case got := <-changes:
		if got != "fingerprint-one" {
			t.Errorf("expected the published fingerprint, got %q", got)
		}
	case <-time.After(time.Second * 10):
		t.Fatal("expected the mapping already published to be reported")
	}

	// And then the builder publishes a new one.
	if err := meta.Tracker().Update(secretResource, &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        "ldap-mapping",
			Namespace:   "kube-oidc-proxy",
			Annotations: map[string]string{fingerprintAnnotation: "fingerprint-two"},
		},
	}, "kube-oidc-proxy"); err != nil {
		t.Fatalf("unexpected error publishing a new mapping: %s", err)
	}

	select {
	case got := <-changes:
		if got != "fingerprint-two" {
			t.Errorf("expected the newly published fingerprint, got %q", got)
		}
	case <-time.After(time.Second * 10):
		t.Fatal("expected the newly published mapping to be reported")
	}
}

// The proxy must not stamp on the other keys of a Secret it shares.
func TestSecretSaveKeepsOtherKeys(t *testing.T) {
	store, client := testSecretStore(t, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ldap-mapping", Namespace: "kube-oidc-proxy"},
		Data:       map[string][]byte{"unrelated": []byte("keep me")},
	})

	if err := store.Save(context.Background(), []byte("mapping"), ""); err != nil {
		t.Fatalf("unexpected error saving: %s", err)
	}

	secret, err := client.CoreV1().Secrets("kube-oidc-proxy").Get(
		context.Background(), "ldap-mapping", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("unexpected error getting the Secret: %s", err)
	}

	if got := string(secret.Data["unrelated"]); got != "keep me" {
		t.Errorf("expected the unrelated key to be kept, got %q", got)
	}
}

func TestSecretLoadTreatsAMissingKeyAsNothingPersisted(t *testing.T) {
	store, _ := testSecretStore(t, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ldap-mapping", Namespace: "kube-oidc-proxy"},
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
		ObjectMeta: metav1.ObjectMeta{Name: "ldap-mapping", Namespace: "kube-oidc-proxy"},
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
		ObjectMeta: metav1.ObjectMeta{Name: "ldap-mapping", Namespace: "kube-oidc-proxy"},
	})

	var updates int
	client.PrependReactor("update", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updates++
		if updates == 1 {
			return true, nil, apierrors.NewConflict(
				corev1.Resource("secrets"), "ldap-mapping", errors.New("the object has been modified"))
		}

		return false, nil, nil
	})

	if err := store.Save(context.Background(), []byte("mapping"), ""); err != nil {
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
				Name: "ldap-mapping", Namespace: "kube-oidc-proxy"}}); err != nil {
				return true, nil, err
			}

			return true, nil, apierrors.NewAlreadyExists(corev1.Resource("secrets"), "ldap-mapping")
		}

		return false, nil, nil
	})

	if err := store.Save(context.Background(), []byte("mapping"), ""); err != nil {
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

	err := store.Save(context.Background(), oversized, "")
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
		"no client": {nil, "kube-oidc-proxy", "ldap-mapping", "mapping.json.gz", "no Kubernetes client"},
		"no name":   {client, "kube-oidc-proxy", "", "mapping.json.gz", "no name configured"},
		"no key":    {client, "kube-oidc-proxy", "ldap-mapping", "", "no key configured"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// A nil *fake.Clientset in an interface is not a nil interface, so
			// pass the untyped nil the caller would.
			var err error
			if test.client == nil {
				_, err = NewSecret(nil, testMetadataClient(), test.namespace, test.name, test.key)
			} else {
				_, err = NewSecret(test.client, testMetadataClient(), test.namespace, test.name, test.key)
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

	store, err := NewSecret(fake.NewSimpleClientset(), testMetadataClient(),
		"", "ldap-mapping", "mapping.json.gz")
	if err != nil {
		t.Fatalf("unexpected error building store: %s", err)
	}

	if store.namespace != "from-the-environment" {
		t.Errorf("expected the namespace to be taken from $%s, got %q", namespaceEnvVar, store.namespace)
	}

	if !strings.Contains(store.String(), "from-the-environment/ldap-mapping") {
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
