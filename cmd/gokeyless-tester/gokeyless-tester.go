package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"regexp"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/client"
	"github.com/cloudflare/gokeyless/tests"
)

var (
	server    string
	certFile  string
	keyFile   string
	caFile    string
	pubkeyDir string
	pubkeyExt *regexp.Regexp
	crtExt    *regexp.Regexp
	workers   int
	testLen   time.Duration
)

func init() {
	flag.StringVar(&certFile, "cert", "client.pem", "Keyless server authentication certificate")
	flag.StringVar(&keyFile, "key", "client-key.pem", "Keyless server authentication key")
	flag.StringVar(&caFile, "ca-file", "keyserver-ca.pem", "Keyless client certificate authority")
	flag.StringVar(&pubkeyDir, "public-key-directory", "keys/", "Directory where certificates are stored with a .crt extension or public keys are stored with .pubkey extension")
	flag.StringVar(&server, "server", "localhost:2407", "Keyless server on which to listen")
	flag.IntVar(&workers, "workers", 8, "Number of concurrent connections to keyserver")
	flag.DurationVar(&testLen, "testlen", 20*time.Second, "test length in seconds")
	flag.IntVar(&log.Level, "loglevel", 1, "Degree of logging")
	flag.Parse()
}

// LoadPEMPubKey attempts to load a public key from PEM.
func LoadPEMPubKey(in []byte) (crypto.PublicKey, error) {
	p, rest := pem.Decode(in)
	if p == nil || len(rest) != 0 {
		return nil, errors.New("couldn't decode public key")
	}
	return x509.ParsePKIXPublicKey(p.Bytes)
}

func main() {
	c, err := client.NewClientFromFile(certFile, keyFile, caFile)
	if err != nil {
		log.Fatal(err)
	}

	privkeys, err := c.RegisterDir(server, pubkeyDir, LoadPEMPubKey)
	if err != nil {
		log.Fatal(err)
	}

	tests.RunServerTests(testLen, workers, c, server, privkeys)
}
