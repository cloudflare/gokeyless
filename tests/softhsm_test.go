package tests

import (
	"crypto"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/client"
	"github.com/cloudflare/gokeyless/server"
	"github.com/cloudflare/gokeyless/internal/test/params"
)


func LoadURI(uri string) (priv crypto.Signer, err error) {
	pk11uri := server.RFC7512Parser(uri)
	return server.LoadPKCS11Key(pk11uri)
}

// Set up compatible server and client for use by tests.
func init() {
	var err error

	log.Level = log.LevelFatal

	s, err = server.NewServerFromFile(nil, serverCert, serverKey, keylessCA)
	if err != nil {
		log.Fatal(err)
	}

	keys := server.NewDefaultKeystore()
	if err := keys.AddFromURI(params.rsaURI, LoadURI); err != nil {
		log.Fatal(err)
	}
	if err := keys.AddFromURI(params.ecdsaURI, LoadURI); err != nil {
		log.Fatal(err)
	}
	s.SetKeystore(keys)

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
