package tests

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"testing"

	"go4.org/testing/functest"

	"github.com/cloudflare/gokeyless"
	"github.com/cloudflare/gokeyless/client"
)

func TestConnect(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	conn, err := remote.Dial(c)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.Ping([]byte("Hello!")); err != nil {
		t.Fatal(err)
	}
}

func TestBlacklist(t *testing.T) {
	// create a new client with blacklist
	blc, err := client.NewClientFromFile(clientCert, clientKey, keyserverCA)
	if err != nil {
		log.Fatal(err)
	}
	blc.ClearBlacklist()
	// add server certificate to blacklist
	for _, cert := range s.Config.Certificates {
		if cert.Leaf == nil {
			if len(cert.Certificate) == 0 {
				t.Fatal("invalid server certificate")
			}
			var err error
			if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
				log.Fatal(err)
			}
		}
		blc.PopulateBlacklistFromCert(cert.Leaf, 3407)
	}

	if _, err := remote.Dial(blc); err == nil {
		t.Fatal("was able to dial blacklisted server")
	}
}

var ptxt = []byte("Hello!")

func hashMsg(h crypto.Hash) []byte {
	msgHash := h.New()
	msgHash.Write(ptxt)
	return msgHash.Sum(nil)
}

func checkSignature(pub crypto.PublicKey, h crypto.Hash, pss bool) func(res functest.Result) error {
	return func(res functest.Result) error {
		if res.Panicked {
			return fmt.Errorf("%v", res.Panic)
		}
		if res.Result[1] != nil {
			return res.Result[1].(error)
		}
		sig := res.Result[0].([]byte)

		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			if pss {
				pssOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
				if err := rsa.VerifyPSS(rsaPub, pssOpts.Hash, hashMsg(h), sig, pssOpts); err != nil {
					return err
				}
			} else {
				if err := rsa.VerifyPKCS1v15(rsaPub, h, hashMsg(h), sig); err != nil {
					return err
				}
			}
		} else if ecdsaPub, ok := pub.(*ecdsa.PublicKey); ok {
			ecdsaSig := new(struct{ R, S *big.Int })
			asn1.Unmarshal(sig, ecdsaSig)
			if !ecdsa.Verify(ecdsaPub, hashMsg(h), ecdsaSig.R, ecdsaSig.S) {
				return errors.New("failed to verify")
			}
		}
		return nil
	}
}

func TestSign(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	f := functest.New((*client.PrivateKey).Sign)
	f.Test(t,
		f.In(&rsaKey.PrivateKey, rand.Reader, hashMsg(crypto.SHA1), crypto.SHA1).Check(
			checkSignature(rsaKey.Public(), crypto.SHA1, false)),
		f.In(&rsaKey.PrivateKey, rand.Reader, hashMsg(crypto.SHA256), crypto.SHA256).Check(
			checkSignature(rsaKey.Public(), crypto.SHA256, false)),
		f.In(&rsaKey.PrivateKey, rand.Reader, hashMsg(crypto.SHA384), crypto.SHA384).Check(
			checkSignature(rsaKey.Public(), crypto.SHA384, false)),
		f.In(&rsaKey.PrivateKey, rand.Reader, hashMsg(crypto.SHA512), crypto.SHA512).Check(
			checkSignature(rsaKey.Public(), crypto.SHA512, false)),

		f.In(ecdsaKey, rand.Reader, hashMsg(crypto.SHA1), crypto.SHA1).Check(
			checkSignature(ecdsaKey.Public(), crypto.SHA1, false)),
		f.In(ecdsaKey, rand.Reader, hashMsg(crypto.SHA256), crypto.SHA256).Check(
			checkSignature(ecdsaKey.Public(), crypto.SHA256, false)),
		f.In(ecdsaKey, rand.Reader, hashMsg(crypto.SHA384), crypto.SHA384).Check(
			checkSignature(ecdsaKey.Public(), crypto.SHA384, false)),
		f.In(ecdsaKey, rand.Reader, hashMsg(crypto.SHA512), crypto.SHA512).Check(
			checkSignature(ecdsaKey.Public(), crypto.SHA512, false)),
	)
}

func TestRSADecrypt(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	var pub *rsa.PublicKey
	var ok bool
	if pub, ok = rsaKey.Public().(*rsa.PublicKey); !ok {
		t.Fatal("couldn't use public key as RSA key")
	}

	var err error
	var c, m []byte
	if c, err = rsa.EncryptPKCS1v15(rand.Reader, pub, ptxt); err != nil {
		t.Fatal(err)
	}

	if m, err = rsaKey.Decrypt(rand.Reader, c, &rsa.PKCS1v15DecryptOptions{}); err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(ptxt, m) != 0 {
		t.Logf("m: %dB\tptxt: %dB", len(m), len(ptxt))
		t.Fatal("rsa decrypt failed")
	}

	if m, err = rsaKey.Decrypt(rand.Reader, c, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: len(ptxt)}); err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(ptxt, m) != 0 {
		t.Logf("m: %dB\tptxt: %dB", len(m), len(ptxt))
		t.Fatal("rsa decrypt failed")
	}

	if m, err = rsaKey.Decrypt(rand.Reader, c, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: len(ptxt) + 1}); err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(ptxt, m) == 0 {
		t.Logf("m: %dB\tptxt: %dB", len(m), len(ptxt))
		t.Fatal("rsa decrypt suceeded despite incorrect SessionKeyLen")
	}
}

func TestGetCertificate(t *testing.T) {
	certChainBytes, _ := ioutil.ReadFile(tlsChain)

	if testing.Short() {
		t.SkipNow()
	}

	conn, err := remote.Dial(c)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	resp, err := conn.DoOperation(&gokeyless.Operation{
		Opcode: gokeyless.OpGetCertificate,
	})
	if err != nil {
		t.Fatal(err)
	} else if bytes.Compare(certChainBytes, resp.Payload) != 0 {
		t.Logf("m: %dB\tcertChain: %dB", len(certChainBytes), len(resp.Payload))
		t.Fatal("certificate chain mismatch")
	}
}
