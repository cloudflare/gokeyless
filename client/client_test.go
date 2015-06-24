package client

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"testing"
)

const (
	certFile  = "testdata/rsa-client.pem"
	keyFile   = "testdata/rsa-client-key.pem"
	caFile    = "testdata/testca-keyserver.pem"
	rsaPubKey = "testdata/rsa.pubkey"
	//rsaPrivKey = "testdata/rsa.key"
	server = "rsa-server:3407"
)

var (
	client *Client
	pkey   *PrivateKey
)

func init() {
	var err error
	var pemBytes []byte
	var pub crypto.PublicKey
	var p *pem.Block

	if client, err = NewClient(certFile, keyFile, caFile); err != nil {
		log.Fatal(err)
	}

	if pemBytes, err = ioutil.ReadFile(rsaPubKey); err != nil {
		log.Fatal(err)
	}
	p, _ = pem.Decode(pemBytes)
	if pub, err = x509.ParsePKIXPublicKey(p.Bytes); err != nil {
		log.Fatal(err)
	}
	if pkey, err = client.RegisterPublicKey(server, pub); err != nil {
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

func TestRSASign(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	conn, err := client.Dial(server)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg := []byte("Hello!")
	h := crypto.SHA256
	sig, err := pkey.Sign(nil, msg, h)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%02x\n", msg)
	hashed := sha256.Sum256(msg)
	if rsaPub, ok := pkey.Public().(*rsa.PublicKey); ok {
		if err := rsa.VerifyPKCS1v15(rsaPub, h, hashed[:], sig); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Fatal("couldn't use public key as RSA key")
	}
}
