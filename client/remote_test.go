package client

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"

	"github.com/cloudflare/gokeyless"
	"github.com/cloudflare/gokeyless/server"
)

const (
	serverCert   = "testdata/server.pem"
	serverKey    = "testdata/server-key.pem"
	keylessCA    = "testdata/ca.pem"
	serverAddr   = "localhost:3407"
	rsaPrivKey   = "testdata/rsa.key"
	ecdsaPrivKey = "testdata/ecdsa.key"

	clientCert  = "testdata/client.pem"
	clientKey   = "testdata/client-key.pem"
	keyserverCA = "testdata/ca.pem"
	rsaPubKey   = "testdata/rsa.pubkey"
	ecdsaPubKey = "testdata/ecdsa.pubkey"
)

var (
	s          *server.Server
	c          *Client
	rsaKey     *PrivateKey
	ecdsaKey   *PrivateKey
	rsaSKI     gokeyless.SKI
	ecdsaSKI   gokeyless.SKI
	remote     Remote
	deadRemote Remote
)

// Set up compatible server and client for use by tests.
func TestMain(t *testing.T) {
	var err error
	var pemBytes []byte
	var p *pem.Block
	var priv crypto.Signer
	var pub crypto.PublicKey

	// Setup keyless server
	s, err = server.NewServerFromFile(serverCert, serverKey, keylessCA, serverAddr, "")
	if err != nil {
		t.Fatal(err)
	}

	if pemBytes, err = ioutil.ReadFile(rsaPrivKey); err != nil {
		t.Fatal(err)
	}
	p, _ = pem.Decode(pemBytes)
	if priv, err = x509.ParsePKCS1PrivateKey(p.Bytes); err != nil {
		t.Fatal(err)
	}
	if err = s.Keys.Add(nil, priv); err != nil {
		t.Fatal(err)
	}

	if pemBytes, err = ioutil.ReadFile(ecdsaPrivKey); err != nil {
		t.Fatal(err)
	}
	p, _ = pem.Decode(pemBytes)
	if priv, err = x509.ParseECPrivateKey(p.Bytes); err != nil {
		t.Fatal(err)
	}
	if err = s.Keys.Add(nil, priv); err != nil {
		t.Fatal(err)
	}

	listening := make(chan bool)
	go func() {
		listening <- true
		if err := s.ListenAndServe(); err != nil {
			t.Fatal(err)
		}
	}()
	<-listening

	// Setup keyless client
	if c, err = NewClientFromFile(clientCert, clientKey, keyserverCA); err != nil {
		t.Fatal(err)
	}

	// start a remote server at serverAddr
	remote, err = c.LookupServer(serverAddr)
	if err != nil {
		t.Fatal(err)
	}

	deadRemote, err = c.LookupServer("localhost:65432")
	if err != nil {
		t.Fatal(err)
	}

	// Make a remote group containing a good server and a bad one.
	// Setup default remote to be the above group
	c.DefaultRemote = remote.Add(deadRemote)

	// register both public keys with empty remote server so
	// DefaultRemote will be used
	if pemBytes, err = ioutil.ReadFile(rsaPubKey); err != nil {
		t.Fatal(err)
	}
	p, _ = pem.Decode(pemBytes)
	if pub, err = x509.ParsePKIXPublicKey(p.Bytes); err != nil {
		t.Fatal(err)
	}
	if rsaSKI, err = gokeyless.GetSKI(pub); err != nil {
		t.Fatal(err)
	}
	if rsaKey, err = c.RegisterPublicKey("", pub); err != nil {
		t.Fatal(err)
	}

	if pemBytes, err = ioutil.ReadFile(ecdsaPubKey); err != nil {
		t.Fatal(err)
	}
	p, _ = pem.Decode(pemBytes)
	if pub, err = x509.ParsePKIXPublicKey(p.Bytes); err != nil {
		t.Fatal(err)
	}
	if ecdsaSKI, err = gokeyless.GetSKI(pub); err != nil {
		t.Fatal(err)
	}
	if ecdsaKey, err = c.RegisterPublicKey("", pub); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteGroup(t *testing.T) {
	_, err := c.Dial(rsaSKI)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.Dial(ecdsaSKI)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBadRemote(t *testing.T) {
	// clear cached remotes and set a bad remote for the client
	c.DefaultRemote = deadRemote
	c.servers = map[string]Remote{}
	c.remotes = map[gokeyless.SKI]Remote{}

	// register the ECDDSA certificate again with the default broken remote
	pemBytes, err := ioutil.ReadFile(ecdsaPubKey)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pem.Decode(pemBytes)
	pub, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if ecdsaKey, err = c.RegisterPublicKey("", pub); err != nil {
		t.Fatal(err)
	}

	_, err = c.Dial(ecdsaSKI)
	if err == nil {
		t.Fatal("bad remote management")
	}
}
