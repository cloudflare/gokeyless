// +build !pkcs11 !cgo

package server

import (
	"crypto"
	"fmt"
)

func loadPKCS11URI(uri string) (crypto.Signer, error) {
	return nil, fmt.Errorf("pkcs#11 support is not enabled")
}
