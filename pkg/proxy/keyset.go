// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// staticKeySet implements oidc.KeySet over public keys given up front, for an
// issuer whose keys are configured rather than discovered. It never makes a
// request, so the issuer does not have to be reachable - and a key the issuer
// rotates to is not picked up until it is configured.
type staticKeySet struct {
	keys []crypto.PublicKey
	algs []jose.SignatureAlgorithm
}

func newStaticKeySet(keys []crypto.PublicKey, signingAlgs []string) *staticKeySet {
	algs := make([]jose.SignatureAlgorithm, 0, len(signingAlgs))
	for _, alg := range signingAlgs {
		algs = append(algs, jose.SignatureAlgorithm(alg))
	}

	return &staticKeySet{keys: keys, algs: algs}
}

// VerifySignature returns the payload of the token if any of the keys signed
// it. The verifier has already checked the algorithm against the issuer's, and
// checks the issuer, audience and expiry of the payload after.
func (s *staticKeySet) VerifySignature(_ context.Context, token string) ([]byte, error) {
	jws, err := jose.ParseSignedCompact(token, s.algs)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt: %w", err)
	}

	// A PEM key carries no key ID to pick it by, so every key is tried.
	for _, key := range s.keys {
		if payload, err := jws.Verify(key); err == nil {
			return payload, nil
		}
	}

	return nil, errors.New("oidc: failed to verify signature: no configured public key matched")
}
