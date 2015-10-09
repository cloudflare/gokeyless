package tests

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"strconv"
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless"
	"github.com/cloudflare/gokeyless/client"
	"github.com/cloudflare/gokeyless/tests/testapi"
)

// hashPtxt hashes the plaintext with the given hash algorithm.
func hashPtxt(h crypto.Hash, ptxt []byte) []byte {
	return h.New().Sum(ptxt)[len(ptxt):]
}

// NewPingTest generates a TestFunc to connect and perform a ping.
func NewPingTest(c *client.Client, server string) testapi.TestFunc {
	return func() error {
		cookie := make([]byte, 512)
		_, err := rand.Read(cookie)
		if err != nil {
			return err
		}
		conn, err := c.Dial(server)
		if err != nil {
			return err
		}
		defer conn.Close()
		return conn.Ping(nil)
	}
}

// NewSignTests generates a map of test name to TestFunc that performs an opaque sign and verify.
func NewSignTests(priv crypto.Signer) map[string]testapi.TestFunc {
	tests := make(map[string]testapi.TestFunc)
	ptxt := []byte("Test Plaintext")
	r := rand.Reader
	hashes := map[string]crypto.Hash{
		"sign.md5sha1": crypto.MD5SHA1,
		"sign.sha1":    crypto.SHA1,
		"sign.sha224":  crypto.SHA224,
		"sign.sha256":  crypto.SHA256,
		"sign.sha384":  crypto.SHA384,
		"sign.sha512":  crypto.SHA512,
	}

	for hashName, h := range hashes {
		var msg []byte
		if h == crypto.MD5SHA1 {
			msg = append(hashPtxt(crypto.MD5, ptxt), hashPtxt(crypto.SHA1, ptxt)...)
		} else {
			msg = hashPtxt(h, ptxt)
		}

		tests[hashName] = func(h crypto.Hash) testapi.TestFunc {
			return func() error {
				sig, err := priv.Sign(r, msg, h)
				if err != nil {
					return err
				}

				switch pub := priv.Public().(type) {
				case *rsa.PublicKey:
					return rsa.VerifyPKCS1v15(pub, h, msg, sig)
				case *ecdsa.PublicKey:
					ecdsaSig := new(struct{ R, S *big.Int })
					asn1.Unmarshal(sig, ecdsaSig)
					if !ecdsa.Verify(pub, msg, ecdsaSig.R, ecdsaSig.S) {
						return errors.New("ecdsa verify failed")
					}
				default:
					return errors.New("unknown public key type")
				}

				return nil
			}
		}(h)
	}
	return tests
}

// NewDecryptTest generates an RSA decryption test.
func NewDecryptTest(decrypter crypto.Decrypter) testapi.TestFunc {
	ptxt := []byte("Test Plaintext")
	r := rand.Reader

	return func() (err error) {
		var c, m []byte
		if c, err = rsa.EncryptPKCS1v15(r, decrypter.Public().(*rsa.PublicKey), ptxt); err != nil {
			return
		}

		if m, err = decrypter.Decrypt(r, c, &rsa.PKCS1v15DecryptOptions{}); err != nil {
			return
		}
		if bytes.Compare(ptxt, m) != 0 {
			return errors.New("rsa decrypt failed")
		}

		if m, err = decrypter.Decrypt(r, c, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: len(ptxt)}); err != nil {
			return
		}
		if bytes.Compare(ptxt, m) != 0 {
			return errors.New("rsa decrypt failed")
		}

		if m, err = decrypter.Decrypt(r, c, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: len(ptxt) + 1}); err != nil {
			return
		}
		if bytes.Compare(ptxt, m) == 0 {
			return errors.New("rsa decrypt suceeded despite incorrect SessionKeyLen")
		}
		return nil
	}
}

func getCertFromDomain(domain string) (*x509.Certificate, error) {
	var host, port string
	var err error
	if host, port, err = net.SplitHostPort(domain); err != nil {
		host = domain
		port = "443"
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", net.JoinHostPort(host, port), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if len(conn.ConnectionState().PeerCertificates) == 0 {
		return nil, errors.New("received no server certificates")
	}

	return conn.ConnectionState().PeerCertificates[0], nil
}

// RunAPITests runs a test suite based on on API Input and returns an API Result.
func RunAPITests(in *testapi.Input, c *client.Client, testLen time.Duration, workers int) (*testapi.Results, error) {
	log.Debugf("Testing %s", in.Keyserver)
	var err error
	var certs []*x509.Certificate

	if len(in.CertsPEM) > 0 {
		log.Debug("Parsing certificate PEM")
		certs, err = helpers.ParseCertificatesPEM([]byte(in.CertsPEM))
		if err != nil {
			log.Warning("Couldn't parse certificate PEM")
			return nil, err
		}
	}

	var sni string
	if in.Domain != "" {
		log.Debugf("Getting certificate from %s", in.Domain)
		if cert, err := getCertFromDomain(in.Domain); err == nil {
			certs = append(certs, cert)
		} else {
			log.Warningf("Couldn't get certificate from %s: %v", in.Domain, err)
		}

		if sni, _, err = net.SplitHostPort(in.Domain); err != nil {
			sni = in.Domain
		}
	}

	c.Config.InsecureSkipVerify = in.InsecureSkipVerify
	serverIP := net.ParseIP(in.ServerIP)

	if newTestLen, err := time.ParseDuration(in.TestLen); err == nil {
		if newTestLen > 0 && newTestLen < 30*time.Second {
			testLen = newTestLen
		}
	}

	if newWorkers, err := strconv.Atoi(in.Workers); err == nil {
		if newWorkers > 0 && newWorkers < 1024 {
			workers = newWorkers
		}
	}

	results := testapi.NewResults()
	results.RegisterTest("ping", NewPingTest(c, in.Keyserver))

	for _, cert := range certs {
		priv, err := c.RegisterPublicKeyTemplate(in.Keyserver, cert.PublicKey, sni, serverIP)
		if err != nil {
			return nil, err
		}

		ski, err := gokeyless.GetSKICert(cert)
		if err != nil {
			return nil, err
		}

		if _, ok := priv.Public().(*rsa.PublicKey); ok {
			results.RegisterTest(ski.String()+"."+"decrypt", NewDecryptTest(priv))
		}

		for name, test := range NewSignTests(priv) {
			results.RegisterTest(ski.String()+"."+name, test)
		}
	}

	results.RunTests(testLen, workers)

	return results, nil
}
