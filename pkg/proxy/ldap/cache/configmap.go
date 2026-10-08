// Copyright Jetstack Ltd. See LICENSE for details.
package cache

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	typed "k8s.io/client-go/kubernetes/typed/core/v1"
)

const ScopeLabel = "kube-oidc-proxy.jetstack.io/cache-scope"
const ManagedLabel = "app.kubernetes.io/managed-by"

// managedBy is the ManagedLabel value of every ConfigMap this cache owns.
const managedBy = "kube-oidc-proxy"

// UserEntry retains the API version even for an invalid record, so it can be
// replaced with an optimistic update without overwriting concurrent repairs.
type UserEntry struct {
	Name            string
	ResourceVersion string
	Record          *UserRecord
	Invalid         error
}

type UserList struct {
	Entries         []UserEntry
	ResourceVersion string
}

type UserStore interface {
	Get(context.Context, string) (UserEntry, error)
	List(context.Context) (UserList, error)
	Upsert(context.Context, *UserRecord, string) (UserEntry, error)
	Watch(context.Context, string) (watch.Interface, error)
	Decode(*corev1.ConfigMap) UserEntry
}

type ConfigMaps struct {
	client      typed.ConfigMapInterface
	scope       string
	fingerprint string
	selector    string
}

func NewConfigMaps(client kubernetes.Interface, namespace, scope, fingerprint string) (*ConfigMaps, error) {
	if client == nil || namespace == "" || scope == "" || fingerprint == "" {
		return nil, errors.New("ConfigMap cache requires client, namespace, scope and fingerprint")
	}
	if errs := validation.IsValidLabelValue(scope); len(errs) != 0 {
		return nil, fmt.Errorf("invalid cache scope: %s", strings.Join(errs, ", "))
	}
	return &ConfigMaps{client: client.CoreV1().ConfigMaps(namespace), scope: scope, fingerprint: fingerprint,
		selector: managedLabels(scope).String()}, nil
}

func managedLabels(scope string) labels.Set {
	return labels.Set{ManagedLabel: managedBy, ScopeLabel: scope}
}

// owns reports whether a ConfigMap carries this cache's managed labels.
func (s *ConfigMaps) owns(cm *corev1.ConfigMap) bool {
	return cm.Labels[ManagedLabel] == managedBy && cm.Labels[ScopeLabel] == s.scope
}

func (s *ConfigMaps) Decode(cm *corev1.ConfigMap) UserEntry {
	e := UserEntry{Name: cm.Name, ResourceVersion: cm.ResourceVersion}
	if !s.owns(cm) {
		e.Invalid = errors.New("ConfigMap is outside managed cache scope")
		return e
	}
	record, err := decodeUserRecord([]byte(cm.Data[UserRecordKey]), s.fingerprint)
	if err != nil {
		e.Invalid = err
		return e
	}
	name, err := UserConfigMapName(s.scope, record.Username)
	if err != nil || name != cm.Name || record.Username != strings.ToLower(record.Username) {
		e.Invalid = errors.New("ConfigMap identity does not match its name")
		return e
	}
	e.Record = record
	return e
}

func (s *ConfigMaps) Get(ctx context.Context, username string) (UserEntry, error) {
	name, err := UserConfigMapName(s.scope, username)
	if err != nil {
		return UserEntry{}, err
	}
	cm, err := s.client.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return UserEntry{}, ErrNotFound
	}
	if err != nil {
		return UserEntry{}, err
	}
	if !s.owns(cm) {
		return UserEntry{}, fmt.Errorf("refusing unmanaged ConfigMap %q", cm.Name)
	}
	return s.Decode(cm), nil
}

func (s *ConfigMaps) List(ctx context.Context) (UserList, error) {
	list, err := s.client.List(ctx, metav1.ListOptions{LabelSelector: s.selector})
	if err != nil {
		return UserList{}, err
	}
	result := UserList{ResourceVersion: list.ResourceVersion}
	for i := range list.Items {
		result.Entries = append(result.Entries, s.Decode(&list.Items[i]))
	}
	return result, nil
}

// Upsert never retries a conflict: the caller must discard the LDAP result and
// reload the committed record. Empty expectedVersion means create only.
func (s *ConfigMaps) Upsert(ctx context.Context, record *UserRecord, expectedVersion string) (UserEntry, error) {
	data, err := EncodeUserRecord(record)
	if err != nil {
		return UserEntry{}, err
	}
	if record.ConfigurationFingerprint != s.fingerprint {
		return UserEntry{}, errors.New("incompatible configuration fingerprint")
	}
	name, err := UserConfigMapName(s.scope, record.Username)
	if err != nil {
		return UserEntry{}, err
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: expectedVersion,
		Labels: managedLabels(s.scope)}, Data: map[string]string{UserRecordKey: string(data)}}
	if expectedVersion == "" {
		cm, err = s.client.Create(ctx, cm, metav1.CreateOptions{})
	} else {
		cm, err = s.client.Update(ctx, cm, metav1.UpdateOptions{})
	}
	if err != nil {
		return UserEntry{}, err
	}
	return s.Decode(cm), nil
}

func (s *ConfigMaps) Watch(ctx context.Context, version string) (watch.Interface, error) {
	return s.client.Watch(ctx, metav1.ListOptions{LabelSelector: s.selector, ResourceVersion: version, AllowWatchBookmarks: true})
}
