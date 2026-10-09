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
	"k8s.io/klog/v2"

	"github.com/jetstack/kube-oidc-proxy/cmd/app/options"
	"github.com/jetstack/kube-oidc-proxy/pkg/leader"
	"github.com/jetstack/kube-oidc-proxy/pkg/probe"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/ldap/cache"
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

			// Initialise Secure Serving Config
			secureServingInfo := new(server.SecureServingInfo)
			if err := opts.SecureServing.ApplyTo(&secureServingInfo); err != nil {
				return err
			}

			proxyConfig := &proxy.Config{
				TokenPassthrough: opts.App.TokenPassthrough.Enabled,

				FlushInterval:   opts.App.FlushInterval,
				ExternalAddress: opts.SecureServing.BindAddress.String(),

				ExtraUserHeaders:                opts.App.ExtraHeaderOptions.ExtraUserHeaders,
				ExtraUserHeadersClientIPEnabled: opts.App.ExtraHeaderOptions.EnableClientIPExtraUserHeader,
			}

			// Client for leader election and the LDAP cache.
			kubeclient, err := kubernetes.NewForConfig(restConfig)
			if err != nil {
				return err
			}

			// Elect one replica leader. Every replica serves requests
			// whether or not it leads.
			namespace, err := util.NamespaceOrInCluster(opts.LeaderElection.ResourceNamespace)
			if err != nil {
				return fmt.Errorf("no --leader-elect-resource-namespace set: %w", err)
			}

			elector, err := leader.New(kubeclient, leader.Config{
				Namespace:     namespace,
				Name:          opts.LeaderElection.ResourceName,
				LeaseDuration: opts.LeaderElection.LeaseDuration.Duration,
				RenewDeadline: opts.LeaderElection.RenewDeadline.Duration,
				RetryPeriod:   opts.LeaderElection.RetryPeriod.Duration,
			})
			if err != nil {
				return err
			}

			// Set up the LDAP backends that the groups of a request are
			// augmented from, if configured. Left nil when they are not, so
			// that the proxy keeps taking groups from the token.
			var ldapDirectory proxy.GroupAugmenter
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

				cacheNamespace, err := util.NamespaceOrInCluster(ldapConfig.Cache.Namespace)
				if err != nil {
					return err
				}
				ldapCache, err := cache.NewConfigMaps(kubeclient, cacheNamespace, ldapConfig.UserRecordFingerprint())
				if err != nil {
					return err
				}
				// Only the leader refreshes cached users periodically.
				directory, err := ldap.NewUserDirectory(ldapConfig, ldapCache, elector.LeadershipContext)
				if err != nil {
					return err
				}

				ldapDirectory = directory

				// Readiness requires initial ConfigMap synchronization, even when empty.
				ldapReadiness = append(ldapReadiness, probe.NamedCheck{
					Name: "ldap cache synchronization",
					Check: func() error {
						if !directory.HasSynced() {
							return errors.New("LDAP cache initial synchronization is incomplete")
						}

						return nil
					},
				})
			}

			if opts.App.TokenPassthrough.Enabled && opts.OIDCAuthentication.ConfigFile != "" {
				klog.Infof("ignoring --oidc-config-file: with --token-passthrough the API server authenticates every request")
			}

			// Initialise proxy with OIDC token authenticator
			p, err := proxy.New(restConfig, opts.OIDCAuthentication, opts.Audit, ldapDirectory,
				secureServingInfo, proxyConfig)
			if err != nil {
				return err
			}

			// Stay unready until the secure listener is accepting.
			ready := probe.Run(strconv.Itoa(opts.App.ReadinessProbePort),
				p.OIDCHealthCheck, ldapReadiness...)

			// Run proxy
			waitCh, listenerStoppedCh, err := p.Run(stopCh)
			if err != nil {
				return err
			}

			// Serve has started accepting requests; allow Service traffic.
			ready.MarkServing()

			// Contended for only once serving, so that a replica that fails
			// to start never holds the Lease.
			electionDone := elector.Run(stopCh)

			<-waitCh
			<-listenerStoppedCh

			// Waited on so that the Lease is released before the process
			// exits, and the next leader can take over at once.
			<-electionDone

			if err := p.RunPreShutdownHooks(); err != nil {
				return err
			}

			return nil
		},
	}
}
