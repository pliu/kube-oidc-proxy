// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/jetstack/kube-oidc-proxy/cmd/app/options"
	"github.com/jetstack/kube-oidc-proxy/pkg/leader"
	"github.com/jetstack/kube-oidc-proxy/pkg/probe"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/tokenreview"
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
			var ldapUsers *ldap.UserDirectory
			var ldapReadiness []probe.NamedCheck
			if opts.LDAP.Enabled() {
				usernamePrefix, err := opts.OIDCAuthentication.SharedUsernamePrefix()
				if err != nil {
					return err
				}

				ldapConfig, err := opts.LDAP.Config(usernamePrefix)
				if err != nil {
					return err
				}

				namespace := ldapConfig.Cache.Namespace
				if namespace == "" {
					namespace, err = cache.InClusterNamespace()
					if err != nil {
						return err
					}
				}
				ldapCache, err := cache.NewConfigMaps(kubeclient, namespace, ldapConfig.Cache.Scope, ldapConfig.UserRecordFingerprint())
				if err != nil {
					return err
				}
				directory, err := ldap.NewUserDirectory(ldapConfig, ldapCache)
				if err != nil {
					return err
				}

				ldapDirectory = directory
				ldapUsers = directory

				// Readiness requires initial ConfigMap synchronization, even when empty.
				ldapReadiness = append(ldapReadiness, probe.NamedCheck{
					Name: "ldap cache synchronization",
					Check: func() error {
						if !directory.HasMapping() {
							return errors.New("LDAP cache initial synchronization is incomplete")
						}

						return nil
					},
				})
			}

			// Elect one replica leader. Every replica serves requests
			// whether or not it leads.
			var elector *leader.Elector
			if opts.LeaderElection.LeaderElect {
				namespace := opts.LeaderElection.ResourceNamespace
				if namespace == "" {
					namespace, err = cache.InClusterNamespace()
					if err != nil {
						return fmt.Errorf("no --leader-elect-resource-namespace set and %s "+
							"(set --leader-elect=false when running outside a cluster)", err)
					}
				}

				elector, err = leader.New(kubeclient, leader.Config{
					Namespace:     namespace,
					Name:          opts.LeaderElection.ResourceName,
					LeaseDuration: opts.LeaderElection.LeaseDuration.Duration,
					RenewDeadline: opts.LeaderElection.RenewDeadline.Duration,
					RetryPeriod:   opts.LeaderElection.RetryPeriod.Duration,
				})
				if err != nil {
					return err
				}
			}

			if ldapUsers != nil && elector != nil {
				ldapUsers.SetLeaderCheck(elector.IsLeader)
			}

			// Initialise proxy with OIDC token authenticator
			p, err := proxy.New(restConfig, opts.OIDCAuthentication, opts.Audit, ldapDirectory,
				tokenReviewer, subectAccessReviewer, secureServingInfo, proxyConfig)
			if err != nil {
				return err
			}

			// Start readiness probe. It stays unready until the secure
			// listener is accepting, so a restored LDAP mapping cannot put
			// the pod in its Service while the first directory sweep is
			// still blocking Run.
			ready := probe.Run(strconv.Itoa(opts.App.ReadinessProbePort),
				p.OIDCHealthCheck, ldapReadiness...)

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

			// Contended for only once serving, so that a replica that fails
			// to start never holds the Lease.
			var electionDone <-chan struct{}
			if elector != nil {
				electionDone = elector.Run(stopCh)
			}

			<-waitCh
			<-listenerStoppedCh

			// Waited on so that the Lease is released before the process
			// exits, and the next leader can take over at once.
			if electionDone != nil {
				<-electionDone
			}

			if err := p.RunPreShutdownHooks(); err != nil {
				return err
			}

			return nil
		},
	}
}
