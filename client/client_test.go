package client

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"testing"
)

const (
	certFile    = "testdata/rsa-client.pem"
	keyFile     = "testdata/rsa-client-key.pem"
	caFile      = "testdata/testca-keyserver.pem"
	rsaPubKey   = "testdata/rsa.pubkey"
	ecdsaPubKey = "testdata/ecdsa.pubkey"
	server      = "rsa-server:3407"
)

var (
	client   *Client
	rsaKey   *PrivateKey
	ecdsaKey *PrivateKey
)

func init() {
	var err error
	var pemBytes []byte
	var pub crypto.PublicKey
	var p *pem.Block

	if client, err = NewClientFromFile(certFile, keyFile, caFile, ioutil.Discard); err != nil {
		log.Fatal(err)
	}

	if pemBytes, err = ioutil.ReadFile(rsaPubKey); err != nil {
		log.Fatal(err)
	}
	p, _ = pem.Decode(pemBytes)
	if pub, err = x509.ParsePKIXPublicKey(p.Bytes); err != nil {
		log.Fatal(err)
	}
	if rsaKey, err = client.RegisterPublicKey(server, pub); err != nil {
		log.Fatal(err)
	}

	if pemBytes, err = ioutil.ReadFile(ecdsaPubKey); err != nil {
		log.Fatal(err)
	}
	p, _ = pem.Decode(pemBytes)
	if pub, err = x509.ParsePKIXPublicKey(p.Bytes); err != nil {
		log.Fatal(err)
	}
	if ecdsaKey, err = client.RegisterPublicKey(server, pub); err != nil {
		log.Fatal(err)
	}
}

func TestConnect(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	conn, err := client.Dial(server)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.Ping([]byte("Hello!")); err != nil {
		t.Fatal(err)
	}
}

var (
	h    = crypto.SHA256
	r    = rand.Reader
	ptxt = []byte("Hello!")
	msg  = h.New().Sum(ptxt)[len(ptxt):]
)

func TestECDSASign(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	conn, err := client.Dial(server)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	sig, err := ecdsaKey.Sign(r, msg, h)
	if err != nil {
		t.Fatal(err)
	}

	if ecdsaPub, ok := ecdsaKey.Public().(*ecdsa.PublicKey); ok {
		ecdsaSig := new(struct{ R, S *big.Int })
		asn1.Unmarshal(sig, ecdsaSig)
		if !ecdsa.Verify(ecdsaPub, msg, ecdsaSig.R, ecdsaSig.S) {
			t.Log("ecdsa verify failed")
		}
	} else {
		t.Fatal("couldn't use public key as ECDSA key")
	}
}

func TestRSASign(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	conn, err := client.Dial(server)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	sig, err := rsaKey.Sign(r, msg, h)
	if err != nil {
		t.Fatal(err)
	}

	if rsaPub, ok := rsaKey.Public().(*rsa.PublicKey); ok {
		if err := rsa.VerifyPKCS1v15(rsaPub, h, msg, sig); err != nil {
			t.Log("rsa verify failed")
		}
	} else {
		t.Fatal("couldn't use public key as RSA key")
	}
}

func TestRSADecrypt(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	conn, err := client.Dial(server)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var pub *rsa.PublicKey
	var ok bool
	if pub, ok = rsaKey.Public().(*rsa.PublicKey); !ok {
		t.Fatal("couldn't use public key as RSA key")
	}

	var c, m []byte
	if c, err = rsa.EncryptPKCS1v15(r, pub, ptxt); err != nil {
		t.Fatal(err)
	}

	if m, err = rsaKey.Decrypt(r, c, &rsa.PKCS1v15DecryptOptions{}); err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(ptxt, m) != 0 {
		t.Logf("m: %dB\tptxt: %dB", len(m), len(ptxt))
		t.Fatal("rsa decrypt failed")
	}

	if m, err = rsaKey.Decrypt(r, c, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: len(ptxt)}); err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(ptxt, m) != 0 {
		t.Logf("m: %dB\tptxt: %dB", len(m), len(ptxt))
		t.Fatal("rsa decrypt failed")
	}

	if m, err = rsaKey.Decrypt(r, c, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: len(ptxt) + 1}); err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(ptxt, m) == 0 {
		t.Logf("m: %dB\tptxt: %dB", len(m), len(ptxt))
		t.Fatal("rsa decrypt suceeded despite incorrect SessionKeyLen")
	}
}
