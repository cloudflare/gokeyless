//go:build !pkcs11 || !cgo
// +build !pkcs11 !cgo

package server

import (
	"fmt"

	"github.com/cloudflare/gokeyless/signer"
)

func loadPKCS11URI(uri string) (signer.CtxSigner, error) {
	return nil, fmt.Errorf("pkcs#11 support is not enabled")
}
