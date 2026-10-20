// Copyright Jetstack Ltd. See LICENSE for details.
package reqctx

import (
	"net/http"
	"time"

	"github.com/sebest/xff"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/transport"
)

type key int

const (
	// impersonationConfigKey is the context key for the impersonation config.
	impersonationConfigKey key = iota

	// clientAddressKey is the context key for the client address.
	clientAddressKey

	// receivedAtKey is the context key for when the request reached the proxy.
	receivedAtKey
)

type ImpersonationRequest struct {
	ImpersonationConfig *transport.ImpersonationConfig
	InboundUser         user.Info
}

// WithImpersonationConfig returns a copy of parent in which contains the impersonation configuration.
func WithImpersonationConfig(req *http.Request, conf *ImpersonationRequest) *http.Request {
	return req.WithContext(request.WithValue(req.Context(), impersonationConfigKey, conf))
}

// ImpersonationConfig returns the impersonation configuration held in the context if existing.
func ImpersonationConfig(req *http.Request) *ImpersonationRequest {
	conf, _ := req.Context().Value(impersonationConfigKey).(*ImpersonationRequest)
	return conf
}

// RemoteAddress will attempt to return the source client address if available
// in the request context. If it is not, it will be gathered from the request
// and entered into the context.
func RemoteAddr(req *http.Request) (*http.Request, string) {
	ctx := req.Context()

	clientAddress, ok := ctx.Value(clientAddressKey).(string)
	if !ok {
		clientAddress = xff.GetRemoteAddr(req)
		req = req.WithContext(request.WithValue(ctx, clientAddressKey, clientAddress))
	}

	return req, clientAddress
}

// WithReceivedAt returns a copy of the request recording when it reached the
// proxy.
func WithReceivedAt(req *http.Request, t time.Time) *http.Request {
	return req.WithContext(request.WithValue(req.Context(), receivedAtKey, t))
}

// ReceivedAt returns when the request reached the proxy, if recorded.
func ReceivedAt(req *http.Request) (time.Time, bool) {
	t, ok := req.Context().Value(receivedAtKey).(time.Time)
	return t, ok
}
