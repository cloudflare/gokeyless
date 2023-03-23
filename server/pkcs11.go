//go:build pkcs11 && cgo
// +build pkcs11,cgo

package server

import (
	"crypto"
	"fmt"

	"github.com/cloudflare/gokeyless/internal/rfc7512"
)

// DefaultLoadURI attempts to load a signer from a PKCS#11 URI.
func DefaultLoadURI(uri string) (crypto.Signer, error) {
	// This wrapper is here in case we want to parse vendor specific values
	// based on the parameters in the URI or perform side operations, such
	// as waiting for network to be up.
	pk11uri, err := rfc7512.ParsePKCS11URI(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pkcs11: %w", err)
	}

	signer, err := rfc7512.LoadPKCS11Signer(pk11uri)
	if err != nil {
		return nil, fmt.Errorf("failed to load pkcs11: %w", err)
	}
	return signer, nil
}

func loadPKCS11URI(uri string) (crypto.Signer, error) {
	return DefaultLoadURI(uri)
}
