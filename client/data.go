package client

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/cloudflare/gokeyless"
)

// servers maps all known certificate digests to keyless server on which it can be found
var servers map[gokeyless.Digest][]string

// RegisterDigest associates the digest of a public key with a particular keyserver.
func RegisterDigest(server string, dgst gokeyless.Digest) {
	servers[dgst] = append(servers[dgst], server)
}

// RegisterCert digests the public key contained in a certificate and associates it with a particular keyserver.
func RegisterCert(server string, cert *x509.Certificate) error {
	var dgst gokeyless.Digest
	dgst = sha256.Sum256(cert.SubjectKeyId)
	switch pkey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		dgst = sha256.Sum256(pkey.N.Bytes())
	case *ecdsa.PublicKey:
		// TODO: this should be consistent with the keyserver, and hopefully SKI...
		dgst = sha256.Sum256(pkey.X.Bytes())
	default:
		return errors.New("gokeyless/client: certificate contains unknown public key type")
	}
	RegisterDigest(server, dgst)
	return nil
}
