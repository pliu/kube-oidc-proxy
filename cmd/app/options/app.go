// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"time"

	"github.com/spf13/pflag"
	cliflag "k8s.io/component-base/cli/flag"

	"github.com/jetstack/kube-oidc-proxy/pkg/util/flags"
)

type KubeOIDCProxyOptions struct {
	ReadinessProbePort int

	FlushInterval time.Duration

	ExtraHeaderOptions ExtraHeaderOptions
	TokenPassthrough   TokenPassthroughOptions
}

type TokenPassthroughOptions struct {
	Enabled bool
}

type ExtraHeaderOptions struct {
	EnableClientIPExtraUserHeader bool

	ExtraUserHeaders map[string][]string
}

func NewKubeOIDCProxyOptions(nfs *cliflag.NamedFlagSets) *KubeOIDCProxyOptions {
	return new(KubeOIDCProxyOptions).AddFlags(nfs.FlagSet("Kube-OIDC-Proxy"))
}

func (k *KubeOIDCProxyOptions) AddFlags(fs *pflag.FlagSet) *KubeOIDCProxyOptions {
	fs.IntVarP(&k.ReadinessProbePort, "readiness-probe-port", "P", 8080,
		"Port to expose readiness probe.")

	fs.DurationVar(&k.FlushInterval, "flush-interval", time.Millisecond*50,
		"Specifies the interval to flush request bodies. If 0ms, "+
			"no periodic flushing is done. A negative value means to flush "+
			"immediately after each write. Streaming requests such as 'kubectl exec' "+
			"will ignore this option and flush immediately.")

	k.TokenPassthrough.AddFlags(fs)
	k.ExtraHeaderOptions.AddFlags(fs)

	return k
}

func (t *TokenPassthroughOptions) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&t.Enabled, "token-passthrough", t.Enabled, ""+
		"(Alpha) Forward every request to the API server as it is, with the "+
		"caller's own bearer token and without impersonation, so that the API "+
		"server authenticates and authorizes it. The proxy does not authenticate "+
		"the token itself, and cannot be combined with --ldap-config-file or extra "+
		"user headers. Requests without a bearer token are refused.")
}

func (e *ExtraHeaderOptions) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&e.EnableClientIPExtraUserHeader, "extra-user-header-client-ip",
		e.EnableClientIPExtraUserHeader, "(Alpha) If enabled, proxied requests will "+
			"include the extra user header 'Impersonate-Extra-Remote-Client-IP: "+
			"<REMOTE_ADDR>' where <REMOTE_ADDR> will contain the remote address of "+
			"the source of the request.")

	fs.Var(flags.NewStringToStringSliceValue(&e.ExtraUserHeaders), "extra-user-headers",
		"(Alpha) A list of key value pairs of extra user headers to pass with "+
			"proxied requests as part of the impersonated request. A single key can "+
			"hold multiple values.")
}
