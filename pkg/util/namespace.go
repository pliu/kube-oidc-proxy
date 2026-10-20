// Copyright Jetstack Ltd. See LICENSE for details.
package util

import (
	"fmt"
	"os"
	"strings"
)

const namespaceEnvVar = "POD_NAMESPACE"
const namespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// NamespaceOrInCluster returns namespace, or the namespace the process is
// running in when it is empty.
func NamespaceOrInCluster(namespace string) (string, error) {
	if namespace != "" {
		return namespace, nil
	}
	return inClusterNamespace()
}

func inClusterNamespace() (string, error) {
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
