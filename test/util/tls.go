// Copyright Jetstack Ltd. See LICENSE for details.
package util

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"

	"k8s.io/client-go/util/cert"
)

type KeyBundle struct {
	CertBytes []byte
	KeyBytes  []byte
	Key       *rsa.PrivateKey
}

func NewTLSSelfSignedCertKey(host string, netIPs []net.IP, dnsNames []string) (*KeyBundle, error) {
	certBytes, keyBytes, err := cert.GenerateSelfSignedCertKey(host, netIPs, dnsNames)
	if err != nil {
		return nil, err
	}

	p, rest := pem.Decode(keyBytes)
	if p == nil || len(rest) != 0 {
		return nil, fmt.Errorf("invalid PEM private key")
	}

	sk, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		return nil, err
	}

	return &KeyBundle{
		CertBytes: certBytes,
		KeyBytes:  keyBytes,
		Key:       sk,
	}, nil
}
