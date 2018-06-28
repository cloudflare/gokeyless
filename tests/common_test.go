package tests

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"io/ioutil"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/client"
	"github.com/cloudflare/gokeyless/internal/test/params"
	"github.com/cloudflare/gokeyless/protocol"
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
	s        *server.Server
	c        *client.Client
	rsaKey   *client.Decrypter
	ecdsaKey *client.PrivateKey
	remote   client.Remote
)

var testSoftHSM bool

type dummySealer struct{}

func (dummySealer) Seal(op *protocol.Operation) (res []byte, err error) {
	if op.Opcode != protocol.OpSeal {
		panic("wrong op")
	} else if string(op.Payload) == "slow" {
		time.Sleep(time.Second)
	}
	res = []byte("OpSeal ")
	res = append(res, op.Payload...)
	return
}

func (dummySealer) Unseal(op *protocol.Operation) (res []byte, err error) {
	if op.Opcode != protocol.OpUnseal {
		panic("wrong op")
	}
	res = []byte("OpUnseal ")
	res = append(res, op.Payload...)
	return
}

type DummyRPC struct{}

func (DummyRPC) Append(in string, out *string) error {
	*out = in + " World"
	return nil
}

func (DummyRPC) Error(_ string, _ *string) error {
	return errors.New("remote rpc error")
}

// helper function reads a pub key from a file and convert it to a signer
func NewRemoteSignerByPubKeyFile(filepath string) (crypto.Signer, error) {
	pemBytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(pemBytes)
	pub, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return nil, err
	}
	s, err := c.NewRemoteSignerByPublicKey("", pub)
	if err != nil {
		return nil, err
	}
	return s, err
}

// Set up compatible server and client for use by tests.
func init() {
	var err error

	log.Level = log.LevelFatal

	flag.BoolVar(&testSoftHSM, "softhsm2", false, "whether to test against SoftHSM2")
	flag.Parse()

	s, err = server.NewServerFromFile(nil, serverCert, serverKey, keylessCA)
	if err != nil {
		log.Fatal(err)
	}

	if !testSoftHSM {
		keys, err := server.NewKeystoreFromDir("testdata", server.DefaultLoadKey)
		if err != nil {
			log.Fatal(err)
		}
		s.SetKeystore(keys)
	} else {
		keys := server.NewDefaultKeystore()
		if err := keys.AddFromURI(params.RSAURI, server.DefaultLoadURI); err != nil {
			log.Fatal(err)
		}
		if err := keys.AddFromURI(params.ECDSAURI, server.DefaultLoadURI); err != nil {
			log.Fatal(err)
		}
		s.SetKeystore(keys)
	}

	s.SetSealer(dummySealer{})
	if err = s.RegisterRPC(DummyRPC{}); err != nil {
		log.Fatal(err)
	}

	listening := make(chan bool)
	go func() {
		listening <- true
		if err := s.ListenAndServe(serverAddr); err != nil {
			log.Fatal(err)
		}
	}()
	<-listening

	c, err = client.NewClientFromFile(clientCert, clientKey, keyserverCA)
	if err != nil {
		log.Fatal(err)
	}

	remote, err = c.LookupServer(serverAddr)
	if err != nil {
		log.Fatal(err)
	}
	c.DefaultRemote = remote

	privKey, err := NewRemoteSignerByPubKeyFile(rsaPubKey)
	if err != nil {
		log.Fatal(err)
	}

	var ok bool
	rsaKey, ok = privKey.(*client.Decrypter)
	if !ok {
		log.Fatal("bad RSA key registration")
	}

	privKey, err = NewRemoteSignerByPubKeyFile(ecdsaPubKey)
	if err != nil {
		log.Fatal(err)
	}

	ecdsaKey, ok = privKey.(*client.PrivateKey)
	if !ok {
		log.Fatal("bad ECDSA key registration")
	}
}
