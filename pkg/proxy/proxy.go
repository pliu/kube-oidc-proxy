// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	ctx "context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"k8s.io/klog/v2"

	"github.com/jetstack/kube-oidc-proxy/cmd/app/options"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/audit"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/context"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/hooks"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/logging"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/tokenreview"
)

const (
	UserHeaderClientIPKey = "Remote-Client-IP"
)

var (
	errUnauthorized          = errors.New("Unauthorized")
	errNoName                = errors.New("No name in OIDC info")
	errNoImpersonationConfig = errors.New("No impersonation configuration in context")
)

type Config struct {
	DisableImpersonation bool
	TokenReview          bool

	FlushInterval   time.Duration
	ExternalAddress string

	ExtraUserHeaders                map[string][]string
	ExtraUserHeadersClientIPEnabled bool
}

type errorHandlerFn func(http.ResponseWriter, *http.Request, error)

type Proxy struct {
	oidcRequestAuther     *bearertoken.Authenticator
	tokenAuther           authenticator.Token
	tokenReviewer         *tokenreview.TokenReview
	subjectAccessReviewer *subjectaccessreview.SubjectAccessReview
	secureServingInfo     *server.SecureServingInfo
	auditor               *audit.Audit

	// ldapDirectory is nil unless LDAP group augmentation is enabled.
	ldapDirectory GroupAugmenter

	restConfig            *rest.Config
	clientTransport       http.RoundTripper
	noAuthClientTransport http.RoundTripper

	config *Config

	hooks       *hooks.Hooks
	handleError errorHandlerFn
}

// implement oidc.CAContentProvider to load
// the ca file from the options
type CAFromFile struct {
	CAFile string
}

func (caFromFile CAFromFile) CurrentCABundleContent() []byte {
	res, _ := os.ReadFile(caFromFile.CAFile)
	return res
}

func New(restConfig *rest.Config,
	oidcOptions *options.OIDCAuthenticationOptions,
	auditOptions *options.AuditOptions,
	ldapDirectory GroupAugmenter,
	tokenReviewer *tokenreview.TokenReview,
	subjectAccessReviewer *subjectaccessreview.SubjectAccessReview,
	ssinfo *server.SecureServingInfo,
	config *Config) (*Proxy, error) {

	// load the CA from the file listed in the options
	caFromFile := CAFromFile{
		CAFile: oidcOptions.CAFile,
	}

	// setup static JWT Auhenticator
	jwtConfig := apiserver.JWTAuthenticator{
		Issuer: apiserver.Issuer{
			URL:                  oidcOptions.IssuerURL,
			Audiences:            []string{oidcOptions.ClientID},
			CertificateAuthority: string(caFromFile.CurrentCABundleContent()),
		},

		ClaimMappings: apiserver.ClaimMappings{
			Username: apiserver.PrefixedClaimOrExpression{
				Claim:  oidcOptions.UsernameClaim,
				Prefix: &oidcOptions.UsernamePrefix,
			},
			Groups: apiserver.PrefixedClaimOrExpression{
				Claim:  oidcOptions.GroupsClaim,
				Prefix: &oidcOptions.GroupsPrefix,
			},
		},
	}

	// generate tokenAuther from oidc config
	tokenAuther, err := oidc.New(ctx.TODO(), oidc.Options{
		CAContentProvider: caFromFile,
		//RequiredClaims:       oidcOptions.RequiredClaims,
		SupportedSigningAlgs: oidcOptions.SigningAlgs,
		JWTAuthenticator:     jwtConfig,
	})
	if err != nil {
		return nil, err
	}

	auditor, err := audit.New(auditOptions, config.ExternalAddress, ssinfo)
	if err != nil {
		return nil, err
	}

	registerMetrics()

	p := &Proxy{
		restConfig:            restConfig,
		hooks:                 hooks.New(),
		tokenReviewer:         tokenReviewer,
		subjectAccessReviewer: subjectAccessReviewer,
		secureServingInfo:     ssinfo,
		config:                config,
		oidcRequestAuther:     bearertoken.New(tokenAuther),
		tokenAuther:           tokenAuther,
		auditor:               auditor,
		// Nil unless LDAP group augmentation is configured.
		ldapDirectory: ldapDirectory,
	}

	return p, nil
}

func (p *Proxy) Run(stopCh <-chan struct{}) (<-chan struct{}, <-chan struct{}, error) {
	// standard round tripper for proxy to API Server
	clientRT, err := p.roundTripperForRestConfig(p.restConfig)
	if err != nil {
		return nil, nil, err
	}
	p.clientTransport = clientRT

	// No auth round tripper for no impersonation
	if p.config.DisableImpersonation || p.config.TokenReview {
		noAuthClientRT, err := p.roundTripperForRestConfig(&rest.Config{
			APIPath: p.restConfig.APIPath,
			Host:    p.restConfig.Host,
			Timeout: p.restConfig.Timeout,
			TLSClientConfig: rest.TLSClientConfig{
				CAFile: p.restConfig.CAFile,
				CAData: p.restConfig.CAData,
			},
		})
		if err != nil {
			return nil, nil, err
		}

		p.noAuthClientTransport = noAuthClientRT
	}

	// get API server url
	url, err := url.Parse(p.restConfig.Host)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse url: %s", err)
	}

	p.handleError = p.newErrorHandler()

	// Set up proxy handler using proxy
	proxyHandler := httputil.NewSingleHostReverseProxy(url)
	proxyHandler.Transport = p
	proxyHandler.ErrorHandler = p.handleError
	proxyHandler.FlushInterval = p.config.FlushInterval

	waitCh, listenerStoppedCh, err := p.serve(proxyHandler, stopCh)
	if err != nil {
		return nil, nil, err
	}

	return waitCh, listenerStoppedCh, nil
}

func (p *Proxy) serve(handler http.Handler, stopCh <-chan struct{}) (<-chan struct{}, <-chan struct{}, error) {
	// Setup proxy handlers
	handler = p.withHandlers(handler)

	// Run auditor
	if err := p.auditor.Run(stopCh); err != nil {
		return nil, nil, err
	}

	// Build the initial user -> group mapping before serving any requests,
	// then keep it refreshed in the background.
	if p.ldapDirectory != nil {
		if err := p.ldapDirectory.Run(stopCh); err != nil {
			return nil, nil, err
		}
	}

	// securely serve using serving config
	waitCh, listenerStoppedCh, err := p.secureServingInfo.Serve(handler, time.Second*60, stopCh)
	if err != nil {
		return nil, nil, err
	}

	return waitCh, listenerStoppedCh, nil
}

// RoundTrip is called last and is used to manipulate the forwarded request using context.
func (p *Proxy) RoundTrip(req *http.Request) (*http.Response, error) {
	// Here we have successfully authenticated so now need to determine whether
	// we need use impersonation or not.

	// If no impersonation then we return here without setting impersonation
	// header but re-introduce the token we removed.
	if context.NoImpersonation(req) {
		token := context.BearerToken(req)
		req.Header.Add("Authorization", token)
		return p.noAuthClientTransport.RoundTrip(req)
	}

	// Get the impersonation headers from the context.
	impersonationConf := context.ImpersonationConfig(req)
	if impersonationConf == nil {
		return nil, errNoImpersonationConfig
	}

	// Set up impersonation request.
	rt := transport.NewImpersonatingRoundTripper(*impersonationConf.ImpersonationConfig, p.clientTransport)

	// Log the request
	logging.LogSuccessfulRequest(req, *impersonationConf.InboundUser, *impersonationConf.ImpersonatedUser)

	// Push request through round trippers to the API server.
	return rt.RoundTrip(req)
}

func (p *Proxy) reviewToken(rw http.ResponseWriter, req *http.Request) bool {
	var remoteAddr string
	req, remoteAddr = context.RemoteAddr(req)

	klog.V(4).Infof("attempting to validate a token in request using TokenReview endpoint(%s)",
		remoteAddr)

	ok, err := p.tokenReviewer.Review(req)
	if err != nil {
		klog.Errorf("unable to authenticate the request via TokenReview due to an error (%s): %s",
			remoteAddr, err)
		return false
	}

	if !ok {
		klog.V(4).Infof("passing request with valid token through (%s)",
			remoteAddr)

		return false
	}

	// No error and ok so passthrough the request
	return true
}

// maxIdleConnsPerHost is how many spare connections to the API server are kept
// warm. Every request this proxy forwards goes to the one host, so the whole
// process shares a single pool and the per-host limit is the only one that
// really applies. Go's default of two would mean all but two connections being
// closed the moment they go idle and dialled again, TLS handshake and all, for
// the next request that needs one.
const maxIdleConnsPerHost = 100

// transportForRestConfig builds the transport that carries proxied requests to
// the API server.
//
// HTTP/2 must stay off. Exec, attach and port forward are HTTP/1.1 protocol
// upgrades, and Go's HTTP/2 transport cannot carry an upgrade, so negotiating
// h2 with the API server would break them outright. This is said explicitly,
// with an empty TLSNextProto, rather than left to fall out of the transport
// having its own TLSClientConfig: rest.TLSConfigFor returns nil for a rest
// config that asked for no TLS settings at all, and a nil TLSClientConfig is
// one of the things that has Go turn HTTP/2 on by itself.
//
// It is also worth knowing before reaching for utilnet.SetTransportDefaults,
// which fills in sensible timeouts and then turns HTTP/2 on.
func transportForRestConfig(config *rest.Config) (*http.Transport, error) {
	// get golang tls config to the API server
	tlsConfig, err := rest.TLSConfigFor(config)
	if err != nil {
		return nil, err
	}

	// create tls transport to request
	return &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,

		// Empty rather than nil, which is what keeps HTTP/2 off.
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},

		MaxIdleConns:        maxIdleConnsPerHost,
		MaxIdleConnsPerHost: maxIdleConnsPerHost,

		// A pooled connection the API server has since forgotten about is only
		// discovered by trying to use it, so idle ones are given up rather than
		// held for the life of the process.
		IdleConnTimeout: 90 * time.Second,

		// Bounds connecting, not the request that follows it, so a request that
		// then streams for hours is unaffected.
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}, nil
}

func (p *Proxy) roundTripperForRestConfig(config *rest.Config) (http.RoundTripper, error) {
	tlsTransport, err := transportForRestConfig(config)
	if err != nil {
		return nil, err
	}

	// get kube transport config form rest client config
	restTransportConfig, err := config.TransportConfig()
	if err != nil {
		return nil, err
	}

	// wrap golang tls config with kube transport round tripper
	clientRT, err := transport.HTTPWrappersForConfig(restTransportConfig, tlsTransport)
	if err != nil {
		return nil, err
	}

	return clientRT, nil
}

// Return the proxy OIDC token authenticator
func (p *Proxy) OIDCTokenAuthenticator() authenticator.Token {
	return p.tokenAuther
}

func (p *Proxy) RunPreShutdownHooks() error {
	return p.hooks.RunPreShutdownHooks()
}
