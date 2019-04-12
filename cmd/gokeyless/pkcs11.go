// +build pkcs11,cgo

package main

import (
	"crypto"

	"github.com/cloudflare/gokeyless/server"
)

func loadURI(uri string) (crypto.Signer, error) {
	return server.DefaultLoadURI(uri)
}
