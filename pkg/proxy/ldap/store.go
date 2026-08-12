// Copyright Jetstack Ltd. See LICENSE for details.
package ldap

import (
	"fmt"

	"k8s.io/client-go/kubernetes"

	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
)

// NewCacheStore builds the store the mapping is persisted to. It returns a nil
// store, and no error, when persistence is not configured.
//
// The client is only needed by the Kubernetes Secret store, and may be nil
// otherwise.
func NewCacheStore(config *CacheConfig, client kubernetes.Interface) (cache.Store, error) {
	if !config.Enabled() {
		return nil, nil
	}

	switch config.Type {
	case CacheTypeFile:
		if config.File == nil {
			return nil, fmt.Errorf("no file configured for the %q mapping cache", config.Type)
		}

		return cache.NewFile(config.File.Path)

	case CacheTypeKubernetesSecret:
		if config.KubernetesSecret == nil {
			return nil, fmt.Errorf("no kubernetesSecret configured for the %q mapping cache", config.Type)
		}

		return cache.NewSecret(client,
			config.KubernetesSecret.Namespace,
			config.KubernetesSecret.Name,
			config.KubernetesSecret.Key)

	default:
		return nil, fmt.Errorf("unknown mapping cache type %q", config.Type)
	}
}
