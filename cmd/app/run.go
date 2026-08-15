// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"errors"
	"strconv"

	"github.com/spf13/cobra"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"

	"github.com/jetstack/kube-oidc-proxy/cmd/app/options"
	"github.com/jetstack/kube-oidc-proxy/pkg/probe"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/tokenreview"
	"github.com/jetstack/kube-oidc-proxy/pkg/util"
)

func NewRunCommand(stopCh <-chan struct{}) *cobra.Command {
	// Build options
	opts := options.New()

	// Build command
	cmd := buildRunCommand(stopCh, opts)

	// Add option flags to command
	opts.AddFlags(cmd)

	return cmd
}

// Proxy command
func buildRunCommand(stopCh <-chan struct{}, opts *options.Options) *cobra.Command {
	return &cobra.Command{
		Use:  options.AppName,
		Long: "kube-oidc-proxy is a reverse proxy to authenticate users to Kubernetes API servers with Open ID Connect Authentication.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(cmd); err != nil {
				return err
			}

			// Here we determine to either use custom or 'in-cluster' client configuration
			var err error
			var restConfig *rest.Config
			if opts.Client.ClientFlagsChanged(cmd) {
				// One or more client flags have been set to use client flag built
				// config
				restConfig, err = opts.Client.ToRESTConfig()
				if err != nil {
					return err
				}

			} else {
				// No client flags have been set so default to in-cluster config
				restConfig, err = rest.InClusterConfig()
				if err != nil {
					return err
				}
			}

			// Set client throttling settings for Kubernetes clients.
			if opts.Client.KubeClientBurst > 0 {
				restConfig.Burst = opts.Client.KubeClientBurst
			}
			if opts.Client.KubeClientQPS > 0 {
				restConfig.QPS = opts.Client.KubeClientQPS
			}

			// Initialise token reviewer if enabled
			var tokenReviewer *tokenreview.TokenReview
			if opts.App.TokenPassthrough.Enabled {
				tokenReviewer, err = tokenreview.New(restConfig, opts.App.TokenPassthrough.Audiences)
				if err != nil {
					return err
				}
			}

			// Initialise Secure Serving Config
			secureServingInfo := new(server.SecureServingInfo)
			if err := opts.SecureServing.ApplyTo(&secureServingInfo); err != nil {
				return err
			}

			proxyConfig := &proxy.Config{
				TokenReview:          opts.App.TokenPassthrough.Enabled,
				DisableImpersonation: opts.App.DisableImpersonation,

				FlushInterval:   opts.App.FlushInterval,
				ExternalAddress: opts.SecureServing.BindAddress.String(),

				ExtraUserHeaders:                opts.App.ExtraHeaderOptions.ExtraUserHeaders,
				ExtraUserHeadersClientIPEnabled: opts.App.ExtraHeaderOptions.EnableClientIPExtraUserHeader,
			}

			// Setup Subject Access Review
			kubeclient, err := kubernetes.NewForConfig(restConfig)
			if err != nil {
				return err
			}

			subectAccessReviewer, err := subjectaccessreview.New(kubeclient.AuthorizationV1().SubjectAccessReviews())

			if err != nil {
				return err
			}

			// Set up the LDAP backends that the groups of a request are
			// augmented from, if configured. Left nil when they are not, so
			// that the proxy keeps taking groups from the token.
			var ldapDirectory proxy.GroupAugmenter
			var ldapReadiness []probe.NamedCheck
			if opts.LDAP.Enabled() {
				ldapConfig, err := opts.LDAP.Config(opts.OIDCAuthentication.UsernamePrefix)
				if err != nil {
					return err
				}

				// Reads a Secret without its data, so that a proxy serving a
				// mapping another one built can check for a newer one without
				// pulling the whole mapping down every time it looks.
				metaclient, err := metadata.NewForConfig(restConfig)
				if err != nil {
					return err
				}

				// The store the built mapping is persisted to. Nil when the
				// configuration does not ask for it to be persisted.
				ldapCache, err := ldap.NewCacheStore(ldapConfig.Cache, kubeclient, metaclient)
				if err != nil {
					return err
				}

				directory, err := ldap.New(ldapConfig, ldapCache)
				if err != nil {
					return err
				}

				ldapDirectory = directory

				// A proxy that has not got hold of a mapping yet would answer
				// every request by stripping the user of their groups, so it
				// stays out of its Service until it has one. This is what a
				// reader waits on while the builder is part way through its
				// first sweep of the directories.
				ldapReadiness = append(ldapReadiness, probe.NamedCheck{
					Name: "ldap mapping",
					Check: func() error {
						if !directory.HasMapping() {
							return errors.New("no LDAP user to group mapping to serve yet")
						}

						return nil
					},
				})
			}

			// Initialise proxy with OIDC token authenticator
			p, err := proxy.New(restConfig, opts.OIDCAuthentication, opts.Audit, ldapDirectory,
				tokenReviewer, subectAccessReviewer, secureServingInfo, proxyConfig)
			if err != nil {
				return err
			}

			// Create a fake JWT to set up readiness probe
			fakeJWT, err := util.FakeJWT(opts.OIDCAuthentication.IssuerURL)
			if err != nil {
				return err
			}

			// Start readiness probe. It stays unready until the secure
			// listener is accepting, so a restored LDAP mapping cannot put
			// the pod in its Service while the first directory sweep is
			// still blocking Run.
			ready := probe.Run(strconv.Itoa(opts.App.ReadinessProbePort),
				fakeJWT, p.OIDCTokenAuthenticator(), ldapReadiness...)

			// Run proxy
			waitCh, listenerStoppedCh, err := p.Run(stopCh)
			if err != nil {
				return err
			}

			// The port is bound before any of this, so an early request
			// would be taken and then left hanging rather than refused.
			// Serve returns once the listener is accepting: mark only then,
			// so the Service cannot route requests that would wait out the
			// first directory sweep.
			ready.MarkServing()

			<-waitCh
			<-listenerStoppedCh

			if err := p.RunPreShutdownHooks(); err != nil {
				return err
			}

			return nil
		},
	}
}
