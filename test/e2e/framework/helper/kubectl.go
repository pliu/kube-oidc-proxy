// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"io"
	"os"
	"os/exec"
)

type Kubectl struct {
	namespace  string
	kubectl    string
	kubeconfig string
}

func (k *Kubectl) DescribeResource(resource, name string) error {
	return k.Run("describe", resource, name)
}

func (h *Helper) Kubectl(ns string) *Kubectl {
	return &Kubectl{
		namespace:  ns,
		kubectl:    h.cfg.Kubectl,
		kubeconfig: h.cfg.KubeConfigPath,
	}
}

func (k *Kubectl) Run(args ...string) error {
	return k.RunWithStdout(os.Stdout, args...)
}

func (k *Kubectl) RunWithStdout(stdout io.Writer, args ...string) error {
	baseArgs := []string{"--kubeconfig", k.kubeconfig}
	if k.namespace == "" {
		baseArgs = append(baseArgs, "--all-namespaces")
	} else {
		baseArgs = append(baseArgs, "--namespace", k.namespace)
	}
	args = append(baseArgs, args...)
	cmd := exec.Command(k.kubectl, args...)
	cmd.Stdout = stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
