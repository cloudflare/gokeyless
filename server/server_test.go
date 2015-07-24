package server

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

const (
	certFile     = "testdata/rsa-server.pem"
	keyFile      = "testdata/rsa-server-key.pem"
	caFile       = "testdata/testca-keyless.pem"
	rsaPrivKey   = "testdata/rsa.key"
	ecdsaPrivKey = "testdata/ecdsa.key"
	addr         = "rsa-server:3407"
	metricsAddr  = "rsa-server:80"
)

var (
	s *Server
)

func init() {
	var err error
	var pemBytes []byte
	var key crypto.Signer
	var p *pem.Block

	s, err = NewServerFromFile(certFile, keyFile, caFile, addr, metricsAddr, os.Stdout)
	if err != nil {
		log.Fatal(err)
	}

	if pemBytes, err = ioutil.ReadFile(rsaPrivKey); err != nil {
		log.Fatal(err)
	}
	p, _ = pem.Decode(pemBytes)
	if key, err = x509.ParsePKCS1PrivateKey(p.Bytes); err != nil {
		log.Fatal(err)
	}
	s.RegisterKey(key)

	if pemBytes, err = ioutil.ReadFile(ecdsaPrivKey); err != nil {
		log.Fatal(err)
	}
	p, _ = pem.Decode(pemBytes)
	if key, err = x509.ParseECPrivateKey(p.Bytes); err != nil {
		log.Fatal(err)
	}
	s.RegisterKey(key)
}

func TestServer(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	t.Fatal(s.ListenAndServe())
}
