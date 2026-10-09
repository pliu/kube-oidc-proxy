// Copyright Jetstack Ltd. See LICENSE for details.
package kind

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/kind/pkg/cluster/nodeutils"
)

const (
	ProxyImageName         = "kube-oidc-proxy-e2e"
	IssuerImageName        = "oidc-issuer-e2e"
	FakeAPIServerImageName = "fake-apiserver-e2e"
	AuditWebhookImageName  = "audit-webhook-e2e"
	OpenLDAPImageName      = "openldap-e2e"
	LDAPLoadgenImageName   = "ldap-loadgen-e2e"

	// KeycloakImage is pulled by the host and loaded into the nodes, so that a
	// run does not depend on the nodes reaching the registry.
	KeycloakImage = "quay.io/keycloak/keycloak:26.3.5"
)

func (k *Kind) LoadAllImages() error {
	if err := k.LoadKubeOIDCProxy(); err != nil {
		return err
	}

	if err := k.LoadIssuer(); err != nil {
		return err
	}

	if err := k.LoadFakeAPIServer(); err != nil {
		return err
	}

	if err := k.LoadAuditWebhook(); err != nil {
		return err
	}

	if err := k.LoadOpenLDAP(); err != nil {
		return err
	}

	if err := k.LoadLDAPLoadgen(); err != nil {
		return err
	}

	if err := k.LoadKeycloak(); err != nil {
		return err
	}

	return nil
}

func (k *Kind) LoadKubeOIDCProxy() error {
	arch, err := k.nodeArch()
	if err != nil {
		return err
	}

	// The Dockerfile copies the binary of the architecture it is built for.
	binPath := filepath.Join(k.rootPath, "./bin", arch, "kube-oidc-proxy")
	mainPath := filepath.Join(k.rootPath, "./cmd/.")

	return k.loadImage(binPath, mainPath, ProxyImageName, k.rootPath)
}

func (k *Kind) LoadIssuer() error {
	binPath := filepath.Join(k.rootPath, "./test/tools/issuer/bin/oidc-issuer-linux")
	dockerfilePath := filepath.Join(k.rootPath, "./test/tools/issuer")
	mainPath := filepath.Join(dockerfilePath, "cmd")

	return k.loadImage(binPath, mainPath, IssuerImageName, dockerfilePath)
}

func (k *Kind) LoadFakeAPIServer() error {
	binPath := filepath.Join(k.rootPath, "./test/tools/fake-apiserver/bin/fake-apiserver-linux")
	dockerfilePath := filepath.Join(k.rootPath, "./test/tools/fake-apiserver")
	mainPath := filepath.Join(dockerfilePath, "cmd")

	return k.loadImage(binPath, mainPath, FakeAPIServerImageName, dockerfilePath)
}

func (k *Kind) LoadAuditWebhook() error {
	binPath := filepath.Join(k.rootPath, "./test/tools/audit-webhook/bin/audit-webhook")
	dockerfilePath := filepath.Join(k.rootPath, "./test/tools/audit-webhook")
	mainPath := filepath.Join(dockerfilePath, "cmd")

	return k.loadImage(binPath, mainPath, AuditWebhookImageName, dockerfilePath)
}

func (k *Kind) LoadOpenLDAP() error {
	if err := k.runCmd("docker", "build", "-t", OpenLDAPImageName,
		filepath.Join(k.rootPath, "./test/tools/openldap")); err != nil {
		return err
	}

	return k.loadDockerImage(OpenLDAPImageName)
}

func (k *Kind) LoadLDAPLoadgen() error {
	binPath := filepath.Join(k.rootPath, "./test/tools/ldap-loadgen/bin/ldap-loadgen")
	dockerfilePath := filepath.Join(k.rootPath, "./test/tools/ldap-loadgen")
	mainPath := filepath.Join(dockerfilePath, "cmd")

	return k.loadImage(binPath, mainPath, LDAPLoadgenImageName, dockerfilePath)
}

func (k *Kind) LoadKeycloak() error {
	arch, err := k.nodeArch()
	if err != nil {
		return err
	}

	if err := k.runCmd("docker", "pull", "--platform=linux/"+arch, KeycloakImage); err != nil {
		return err
	}

	return k.loadDockerImage(KeycloakImage)
}

func (k *Kind) loadImage(binPath, mainPath, image, dockerfilePath string) error {
	log.Infof("kind: building %q", mainPath)

	if err := os.MkdirAll(filepath.Dir(binPath), 0755); err != nil {
		return err
	}

	err := k.runCmd("go", "build", "-v", "-o", binPath, mainPath)
	if err != nil {
		return err
	}

	err = k.runCmd("docker", "build", "-t", image, dockerfilePath)
	if err != nil {
		return err
	}

	return k.loadDockerImage(image)
}

// loadDockerImage copies an image from the host's Docker into every node.
func (k *Kind) loadDockerImage(image string) error {
	tmpDir, err := ioutil.TempDir(os.TempDir(), "kube-oidc-proxy-e2e")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	imageArchive := filepath.Join(tmpDir, "image.tar")
	log.Infof("kind: saving image %q to archive %q", image, imageArchive)

	arch, err := k.nodeArch()
	if err != nil {
		return err
	}

	// Only the nodes' platform: a pulled multi-platform image is not held
	// locally for the others.
	err = k.runCmd("docker", "save", "--platform=linux/"+arch, "--output="+imageArchive, image)
	if err != nil {
		return err
	}

	nodes, err := k.Nodes()
	if err != nil {
		return err
	}

	b, err := ioutil.ReadFile(imageArchive)
	if err != nil {
		return err
	}

	for _, node := range nodes {
		log.Infof("kind: loading image %q to node %q", image, node.String())
		r := bytes.NewBuffer(b)
		if err := nodeutils.LoadImageArchive(node, r); err != nil {
			return err
		}

		err := node.Command("mkdir", "-p", "/tmp/kube-oidc-proxy").Run()
		if err != nil {
			return fmt.Errorf("failed to create directory %q: %s",
				"/tmp/kube-oidc-proxy", err)
		}
	}

	return nil
}

// nodeArch returns the architecture of the Docker daemon, which runs the kind
// nodes, so that binaries are built for the nodes rather than for the host
// the tests happen to run on.
func (k *Kind) nodeArch() (string, error) {
	if k.arch != "" {
		return k.arch, nil
	}

	out, err := exec.Command("docker", "version", "--format", "{{.Server.Arch}}").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get the docker server architecture: %s", err)
	}

	k.arch = strings.TrimSpace(string(out))
	return k.arch, nil
}

func (k *Kind) runCmd(command string, args ...string) error {
	return k.runCmdWithOut(os.Stdout, command, args...)
}

func (k *Kind) runCmdWithOut(w io.Writer, command string, args ...string) error {
	arch, err := k.nodeArch()
	if err != nil {
		return err
	}

	log.Infof("kind: running command '%s %s'", command, strings.Join(args, " "))
	cmd := exec.Command(command, args...)

	cmd.Stderr = os.Stderr
	cmd.Stdout = w
	cmd.Env = append(os.Environ(),
		"GO111MODULE=on", "CGO_ENABLED=0",
		"GOARCH="+arch, "GOOS=linux")

	if err := cmd.Start(); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		return err
	}

	return nil
}
