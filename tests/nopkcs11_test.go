// +build !pkcs11 !cgo

package tests

import (
	"crypto"
	"fmt"
)

func loadURI(uri string) (crypto.Signer, error) {
	return nil, fmt.Errorf("pkcs#11 support is not enabled")
}
