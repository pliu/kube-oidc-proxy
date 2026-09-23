// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	ctx "context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func sign(t *testing.T, alg jose.SignatureAlgorithm, key interface{}, payload string) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, nil)
	if err != nil {
		t.Fatalf("unexpected error creating signer: %s", err)
	}

	jws, err := signer.Sign([]byte(payload))
	if err != nil {
		t.Fatalf("unexpected error signing: %s", err)
	}

	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("unexpected error serializing: %s", err)
	}

	return token
}

func TestStaticKeySet(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unexpected error generating key: %s", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unexpected error generating key: %s", err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unexpected error generating key: %s", err)
	}

	keySet := newStaticKeySet([]crypto.PublicKey{&rsaKey.PublicKey, &ecKey.PublicKey}, []string{"RS256", "ES256"})

	tests := map[string]struct {
		token  string
		expErr bool
	}{
		"signed by the first key": {
			token: sign(t, jose.RS256, rsaKey, `{"sub":"a"}`),
		},
		// Every key is tried, not only the first.
		"signed by the second key": {
			token: sign(t, jose.ES256, ecKey, `{"sub":"a"}`),
		},
		"signed by a key not in the set": {
			token:  sign(t, jose.RS256, otherKey, `{"sub":"a"}`),
			expErr: true,
		},
		"signed with an algorithm not in the set": {
			token:  sign(t, jose.RS384, rsaKey, `{"sub":"a"}`),
			expErr: true,
		},
		"not a jwt": {
			token:  "not.a.jwt",
			expErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			payload, err := keySet.VerifySignature(ctx.Background(), test.token)
			if test.expErr {
				if err == nil {
					t.Errorf("expected an error, got payload %q", payload)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			if string(payload) != `{"sub":"a"}` {
				t.Errorf("expected the signed payload, got %q", payload)
			}
		})
	}
}
