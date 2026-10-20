// Copyright Jetstack Ltd. See LICENSE for details.
package cache

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	typed "k8s.io/client-go/kubernetes/typed/core/v1"
)

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
	fingerprint string
}

func NewConfigMaps(client kubernetes.Interface, namespace, fingerprint string) (*ConfigMaps, error) {
	if client == nil || namespace == "" || fingerprint == "" {
		return nil, errors.New("ConfigMap cache requires client, namespace and fingerprint")
	}
	return &ConfigMaps{client: client.CoreV1().ConfigMaps(namespace), fingerprint: fingerprint}, nil
}

// managedLabels marks, selects and identifies every ConfigMap this cache owns.
var managedLabels = labels.Set{ManagedLabel: managedBy}

// owns reports whether a ConfigMap carries this cache's managed label.
func owns(cm *corev1.ConfigMap) bool {
	return cm.Labels[ManagedLabel] == managedBy
}

func (s *ConfigMaps) Decode(cm *corev1.ConfigMap) UserEntry {
	e := UserEntry{Name: cm.Name, ResourceVersion: cm.ResourceVersion}
	if !owns(cm) {
		e.Invalid = errors.New("ConfigMap is not managed by kube-oidc-proxy")
		return e
	}
	record, err := decodeUserRecord([]byte(cm.Data[UserRecordKey]), s.fingerprint)
	if err != nil {
		e.Invalid = err
		return e
	}
	name, err := UserConfigMapName(record.Username)
	if err != nil || name != cm.Name || record.Username != strings.ToLower(record.Username) {
		e.Invalid = errors.New("ConfigMap identity does not match its name")
		return e
	}
	e.Record = record
	return e
}

// Get returns the record stored under username's ConfigMap name. Another
// username can share that name; its record is then returned as Invalid, with
// its version, so the caller can replace it rather than serve its groups.
func (s *ConfigMaps) Get(ctx context.Context, username string) (UserEntry, error) {
	name, err := UserConfigMapName(username)
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
	if !owns(cm) {
		return UserEntry{}, fmt.Errorf("refusing unmanaged ConfigMap %q", cm.Name)
	}
	e := s.Decode(cm)
	if e.Record != nil && e.Record.Username != username {
		e.Invalid = fmt.Errorf("ConfigMap %q holds the record of %q", cm.Name, e.Record.Username)
		e.Record = nil
	}
	return e, nil
}

func (s *ConfigMaps) List(ctx context.Context) (UserList, error) {
	list, err := s.client.List(ctx, metav1.ListOptions{LabelSelector: managedLabels.String()})
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
	name, err := UserConfigMapName(record.Username)
	if err != nil {
		return UserEntry{}, err
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: expectedVersion,
		Labels: maps.Clone(managedLabels)}, Data: map[string]string{UserRecordKey: string(data)}}
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
	return s.client.Watch(ctx, metav1.ListOptions{LabelSelector: managedLabels.String(), ResourceVersion: version, AllowWatchBookmarks: true})
}
