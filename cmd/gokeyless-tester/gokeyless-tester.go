package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/cloudflare/cfssl/helpers"
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
	pubkeyExt = regexp.MustCompile(`.+\.pubkey`)
	crtExt = regexp.MustCompile(`.+\.crt`)
	flag.StringVar(&certFile, "cert", "client.pem", "Keyless server authentication certificate")
	flag.StringVar(&keyFile, "key", "client-key.pem", "Keyless server authentication key")
	flag.StringVar(&caFile, "ca-file", "keyserver-ca.pem", "Keyless client certificate authority")
	flag.StringVar(&pubkeyDir, "public-key-directory", "keys/", "Directory in which public keys are stored with .pubkey extension")
	flag.StringVar(&server, "server", "localhost:2407", "Keyless server on which to listen")
	flag.IntVar(&workers, "workers", 8, "Number of concurrent connections to keyserver")
	flag.DurationVar(&testLen, "testlen", 20*time.Second, "test length in seconds")
	flag.IntVar(&log.Level, "loglevel", 1, "Degree of logging")
	flag.Parse()
}

func main() {
	c, err := client.NewClientFromFile(certFile, keyFile, caFile)
	if err != nil {
		log.Fatal(err)
	}

	var privkeys []*client.PrivateKey

	pubkeys, err := LoadPubKeysFromDir(pubkeyDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, pub := range pubkeys {
		if priv, err := c.RegisterPublicKey(server, pub); err == nil {
			privkeys = append(privkeys, priv)
		} else {
			log.Fatal(err)
		}
	}

	certs, err := LoadCertsFromDir(pubkeyDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, cert := range certs {
		if priv, err := c.RegisterCert(server, cert); err == nil {
			privkeys = append(privkeys, priv)
		} else {
			log.Fatal(err)
		}
	}

	tests.RunServerTests(testLen, workers, c, server, privkeys)
}

// LoadPubKey attempts to load a public key from PEM or DER.
func LoadPubKey(in []byte) (priv crypto.PublicKey, err error) {
	p, rest := pem.Decode(in)
	if p != nil && len(rest) == 0 {
		in = p.Bytes
	}

	return x509.ParsePKIXPublicKey(in)
}

// LoadPubKeysFromDir reads all .pubkey files from a directory and returns associated PublicKey structs.
func LoadPubKeysFromDir(dir string) (pubkeys []crypto.PublicKey, err error) {
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && pubkeyExt.MatchString(info.Name()) {
			log.Infof("Loading %s...\n", path)
			in, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			priv, err := LoadPubKey(in)
			if err != nil {
				return err
			}

			pubkeys = append(pubkeys, priv)
		}
		return nil
	})
	return
}

// LoadCertsFromDir reads all .crt files from a directory and returns associated Certificates.
func LoadCertsFromDir(dir string) (certs []*x509.Certificate, err error) {
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && crtExt.MatchString(info.Name()) {
			log.Infof("Loading %s...\n", path)
			certPEM, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			cert, err := helpers.ParseCertificatePEM(certPEM)
			if err != nil {
				return err
			}

			certs = append(certs, cert)
		}
		return nil
	})
	return
}
