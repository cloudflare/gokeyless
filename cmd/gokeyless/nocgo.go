// +build !cgo

package main

import (
	"crypto"
	"fmt"
)

func loadURI(uri string) (crypto.Signer, error) {
	return nil, fmt.Errorf("this binary was built with cgo disabled, therefore pkcs#11 is not supported")
}
