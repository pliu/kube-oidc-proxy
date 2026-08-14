// Copyright Jetstack Ltd. See LICENSE for details.
package cache

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	k8scache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
)

const (
	// namespaceFile holds the namespace of the pod the proxy is running in.
	namespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

	// namespaceEnvVar is the conventional name of the downward API environment
	// variable holding the namespace, and takes precedence over the service
	// account file.
	namespaceEnvVar = "POD_NAMESPACE"

	// maxSecretSize is the size limit the API server places on the data of a
	// Secret. Exceeding it fails the write, so it is worth a clear error.
	maxSecretSize = 1024 * 1024

	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "kube-oidc-proxy"

	// fingerprintAnnotation identifies the mapping the Secret holds. It is
	// read on its own, without the mapping, by every proxy watching for a
	// newer one, and compared before a write so that a Secret already holding
	// this mapping is not rewritten by another proxy that also built it.
	fingerprintAnnotation = "ldap.kube-oidc-proxy.jetstack.io/mapping-fingerprint"

	// watchResyncPeriod is how often the watch replays what it is holding. A
	// watch that is working needs none of this - a change arrives as it
	// happens - so it is only a floor under how long a change could go
	// unnoticed if one were ever dropped without the connection breaking.
	watchResyncPeriod = time.Minute * 30
)

// Secret persists the mapping into the data of a Kubernetes Secret, so that it
// survives a restart without the proxy needing a volume of its own.
//
// It only suits a directory that stays well inside the 1MiB the API server
// allows a Secret. Gzipping the payload, which is interned before it gets here,
// buys room for something like 45,000 users in ten groups each - but a mapping
// grows with the directory and this limit does not, so a large directory has to
// be persisted to a file. Save refuses a mapping that does not fit rather than
// letting the write fail.
//
// There is also no partial write: any change to the mapping, however small,
// rewrites the whole of it. A Secret this size is not a cheap object to keep
// rewriting - it goes through etcd and out to everything watching it - which is
// why a rebuild that changed nothing is not written at all.
type Secret struct {
	client kubernetes.Interface

	// meta reads the object without its data, which is how a proxy serving a
	// mapping somebody else built checks for a newer one without pulling the
	// mapping down every time it looks.
	meta metadata.Interface

	namespace string
	name      string
	key       string
}

var (
	_ Store         = &Secret{}
	_ Fingerprinter = &Secret{}
	_ Watcher       = &Secret{}

	secretResource = corev1.SchemeGroupVersion.WithResource("secrets")
)

func NewSecret(client kubernetes.Interface, meta metadata.Interface, namespace, name, key string) (*Secret, error) {
	if client == nil {
		return nil, errors.New("no Kubernetes client available to persist the mapping to a Secret")
	}

	if meta == nil {
		return nil, errors.New("no Kubernetes metadata client available to check the Secret holding the mapping")
	}

	if name == "" {
		return nil, errors.New("no name configured for the Secret mapping cache")
	}

	if key == "" {
		return nil, errors.New("no key configured for the Secret mapping cache")
	}

	if namespace == "" {
		// Defaulting to the namespace of the proxy keeps the common in-cluster
		// case free of configuration.
		inCluster, err := InClusterNamespace()
		if err != nil {
			return nil, fmt.Errorf("no namespace configured for the Secret mapping cache and %s", err)
		}

		namespace = inCluster
	}

	return &Secret{
		client:    client,
		meta:      meta,
		namespace: namespace,
		name:      name,
		key:       key,
	}, nil
}

// InClusterNamespace returns the namespace the proxy is running in.
func InClusterNamespace() (string, error) {
	if namespace := strings.TrimSpace(os.Getenv(namespaceEnvVar)); namespace != "" {
		return namespace, nil
	}

	namespace, err := os.ReadFile(namespaceFile)
	if err != nil {
		return "", fmt.Errorf("failed to determine it from the environment: neither $%s nor %s is available: %s",
			namespaceEnvVar, namespaceFile, err)
	}

	if trimmed := strings.TrimSpace(string(namespace)); trimmed != "" {
		return trimmed, nil
	}

	return "", fmt.Errorf("failed to determine it from the environment: %s is empty", namespaceFile)
}

func (s *Secret) Load(ctx context.Context) ([]byte, error) {
	secret, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get Secret %s/%s: %s", s.namespace, s.name, err)
	}

	data, ok := secret.Data[s.key]
	if !ok || len(data) == 0 {
		return nil, ErrNotFound
	}

	decompressed, err := decompress(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress key %q of Secret %s/%s: %s",
			s.key, s.namespace, s.name, err)
	}

	return decompressed, nil
}

// Fingerprint returns the mapping the Secret is holding, read without the
// mapping itself: the request asks for object metadata alone, so a proxy
// polling for a newer mapping does not pull a megabyte off the wire to find
// out that nothing has changed.
func (s *Secret) Fingerprint(ctx context.Context) (string, error) {
	meta, err := s.meta.Resource(secretResource).Namespace(s.namespace).
		Get(ctx, s.name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("failed to get the metadata of Secret %s/%s: %s", s.namespace, s.name, err)
	}

	// Metadata says nothing about whether the key holds anything, so a Secret
	// that exists without the mapping in it reports the empty fingerprint of a
	// Secret written by something else. Either way there is nothing to serve
	// and nothing worth fetching.
	fingerprint, ok := meta.Annotations[fingerprintAnnotation]
	if !ok {
		return "", ErrNotFound
	}

	return fingerprint, nil
}

// Watch reports every change to the Secret until stopCh is closed.
//
// Only the metadata of the object is watched, so what arrives on a change is
// the fingerprint rather than the mapping - the mapping is fetched afterwards,
// and only when the fingerprint says it is worth fetching. The list and watch
// are narrowed to this one Secret by a field selector, though note that RBAC
// cannot be: a role granting watch grants it over every Secret in the
// namespace, whatever the request then asks for.
func (s *Secret) Watch(stopCh <-chan struct{}, onChange func(fingerprint string)) error {
	informer := metadatainformer.NewFilteredMetadataInformer(s.meta, secretResource, s.namespace,
		watchResyncPeriod, k8scache.Indexers{},
		func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("metadata.name", s.name).String()
		},
	).Informer()

	changed := func(object interface{}) {
		meta, ok := object.(*metav1.PartialObjectMetadata)
		if !ok || meta.Name != s.name {
			return
		}

		fingerprint, ok := meta.Annotations[fingerprintAnnotation]
		if !ok {
			// A Secret with no fingerprint on it holds no mapping of ours, and
			// telling the caller it now holds "" would have it throw away a
			// good mapping for an empty one.
			return
		}

		onChange(fingerprint)
	}

	if _, err := informer.AddEventHandler(k8scache.ResourceEventHandlerFuncs{
		AddFunc:    changed,
		UpdateFunc: func(_, object interface{}) { changed(object) },
	}); err != nil {
		return fmt.Errorf("failed to watch Secret %s/%s: %s", s.namespace, s.name, err)
	}

	go informer.Run(stopCh)

	// Returning before the first list is complete would leave the caller
	// unable to tell "nothing published yet" from "not looking yet".
	if !k8scache.WaitForCacheSync(stopCh, informer.HasSynced) {
		return fmt.Errorf("gave up waiting to watch Secret %s/%s", s.namespace, s.name)
	}

	return nil
}

func (s *Secret) Save(ctx context.Context, data []byte, fingerprint string) error {
	compressed, err := compress(data)
	if err != nil {
		return fmt.Errorf("failed to compress the mapping: %s", err)
	}

	if len(compressed) > maxSecretSize {
		return fmt.Errorf("the compressed mapping is %d bytes, over the %d byte limit of Secret %s/%s: "+
			"this directory is too large for a Secret to hold its mapping, so persist to a file "+
			"instead, or narrow the configured search bases",
			len(compressed), maxSecretSize, s.namespace, s.name)
	}

	secrets := s.client.CoreV1().Secrets(s.namespace)

	// Another replica of the proxy refreshes on its own schedule and writes the
	// same Secret, so a conflict here is expected rather than exceptional.
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		secret, err := secrets.Get(ctx, s.name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, err = secrets.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        s.name,
					Namespace:   s.namespace,
					Labels:      map[string]string{managedByLabel: managedByValue},
					Annotations: map[string]string{fingerprintAnnotation: fingerprint},
				},
				Data: map[string][]byte{s.key: compressed},
			}, metav1.CreateOptions{})

			// Lost the race with another replica creating it; the retry sees
			// the Secret and updates it instead.
			if apierrors.IsAlreadyExists(err) {
				return apierrors.NewConflict(corev1.Resource("secrets"), s.name, err)
			}

			if err != nil {
				return fmt.Errorf("failed to create Secret %s/%s: %s", s.namespace, s.name, err)
			}

			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to get Secret %s/%s: %s", s.namespace, s.name, err)
		}

		secret = secret.DeepCopy()
		if secret.Data == nil {
			secret.Data = make(map[string][]byte, 1)
		}
		secret.Data[s.key] = compressed

		// Stamped in the same write as the mapping it describes, so the two
		// cannot come apart: whoever reads the annotation next is told about
		// the mapping that is actually in the object.
		if secret.Annotations == nil {
			secret.Annotations = make(map[string]string, 1)
		}
		secret.Annotations[fingerprintAnnotation] = fingerprint

		if _, err := secrets.Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
			if apierrors.IsConflict(err) {
				return err
			}

			return fmt.Errorf("failed to update Secret %s/%s: %s", s.namespace, s.name, err)
		}

		return nil
	})
}

func (s *Secret) String() string {
	return fmt.Sprintf("Secret %s/%s key %q", s.namespace, s.name, s.key)
}

func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func decompress(data []byte) ([]byte, error) {
	// Tolerate an uncompressed payload so that a Secret written by hand, or by
	// an older proxy, can still be read back.
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return data, nil
	}

	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// Bound the read so that a crafted payload cannot expand without limit.
	decompressed, err := io.ReadAll(io.LimitReader(reader, maxSecretSize*64))
	if err != nil {
		return nil, err
	}

	return decompressed, nil
}
