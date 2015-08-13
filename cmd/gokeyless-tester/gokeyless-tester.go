package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"flag"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/client"
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

	log.Infof("Testing %s for %v with %d workers...", server, testLen, workers)
	errCount := 0

	errs := loadTest(func() error {
		if err := testConnect(c, server); err != nil {
			return err
		}

		for _, key := range privkeys {
			if err := testKey(key); err != nil {
				return err
			}
		}
		return nil
	})

	done := time.After(testLen)
	for {
		select {
		case err := <-errs:
			log.Error(err)
			errCount++

		case <-done:
			log.Infof("Completed with %d errors", errCount)
			return
		}
	}
}

func loadTest(test func() error) <-chan error {
	errs := make(chan error)
	for i := 0; i < workers; i++ {
		go func() {
			for {
				if err := test(); err != nil {
					errs <- err
				}
			}
		}()
	}
	return errs
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

func testConnect(c *client.Client, server string) error {
	conn, err := c.Dial(server)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Ping(nil)
}

func hashPtxt(h crypto.Hash, ptxt []byte) []byte {
	return h.New().Sum(ptxt)[len(ptxt):]
}

func testKey(key *client.PrivateKey) (err error) {
	ptxt := []byte("Hello!")
	r := rand.Reader
	hashes := []crypto.Hash{
		crypto.MD5SHA1,
		crypto.SHA1,
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
	}

	for _, h := range hashes {
		var msg, sig []byte
		if h == crypto.MD5SHA1 {
			msg = append(hashPtxt(crypto.MD5, ptxt), hashPtxt(crypto.SHA1, ptxt)...)
		} else {
			msg = hashPtxt(h, ptxt)
		}

		if sig, err = key.Sign(r, msg, h); err != nil {
			return
		}

		switch pub := key.Public().(type) {
		case *rsa.PublicKey:
			if err = rsa.VerifyPKCS1v15(pub, h, msg, sig); err != nil {
				return
			}
		case *ecdsa.PublicKey:
			ecdsaSig := new(struct{ R, S *big.Int })
			asn1.Unmarshal(sig, ecdsaSig)
			if !ecdsa.Verify(pub, msg, ecdsaSig.R, ecdsaSig.S) {
				return errors.New("ecdsa verify failed")
			}
		default:
			return errors.New("unknown public key type")
		}
	}

	if pub, ok := key.Public().(*rsa.PublicKey); ok {
		var c, m []byte
		if c, err = rsa.EncryptPKCS1v15(r, pub, ptxt); err != nil {
			return
		}

		if m, err = key.Decrypt(r, c, &rsa.PKCS1v15DecryptOptions{}); err != nil {
			return
		}
		if bytes.Compare(ptxt, m) != 0 {
			return errors.New("rsa decrypt failed")
		}

		if m, err = key.Decrypt(r, c, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: len(ptxt)}); err != nil {
			return
		}
		if bytes.Compare(ptxt, m) != 0 {
			return errors.New("rsa decrypt failed")
		}

		if m, err = key.Decrypt(r, c, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: len(ptxt) + 1}); err != nil {
			return
		}
		if bytes.Compare(ptxt, m) == 0 {
			return errors.New("rsa decrypt suceeded despite incorrect SessionKeyLen")
		}
	}

	return nil
}
