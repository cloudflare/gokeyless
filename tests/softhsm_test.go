package tests

import (
	"crypto"

	"github.com/thalesignite/crypto11"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/client"
	"github.com/cloudflare/gokeyless/server"
)

const (
	// testdata/tokens/b01b1e37-d655-6f75-917c-52054b8e924a -> /var/lib/softhsm/tokens/
	rsaPK11URI   = "pkcs11:token=SoftHSM2%20RSA%20Token;id=%03;slot-id=43989470?module-path=/usr/lib64/libsofthsm2.so&pin-value=1234"
	// testdata/tokens/d6a8ab57-d5c5-aaf0-70b6-d01595c28127 -> /var/lib/softhsm/tokens/
	ecdsaPK11URI = "pkcs11:token=SoftHSM2%20EC%20Token;id=%02;slot-id=1400733853?module-path=/usr/lib64/libsofthsm2.so&pin-value=12345"
)

// LoadURI attempts to load a signer from a PKCS#11 URI.
// See https://tools.ietf.org/html/rfc7512#section-2.3
func LoadURI(pk11uri server.PKCS11URI) (priv crypto.Signer, err error) {
	config := &crypto11.PKCS11Config {
		Path:        pk11uri.ModulePath,
		TokenSerial: pk11uri.Serial,
		TokenLabel:  pk11uri.Token,
		Pin:         pk11uri.PinValue,
	}

	_, err = crypto11.Configure(config)
	if err != nil {
		log.Warning(err)
		return nil, err
	}

	key, err := crypto11.FindKeyPairOnSlot(pk11uri.SlotId, pk11uri.Id, pk11uri.Object)
	if err != nil {
		log.Warning(err)
		return nil, err
	}

	return key.(crypto.Signer), nil
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
	if err := keys.AddFromURI(rsaPK11URI, LoadURI); err != nil {
		log.Fatal(err)
	}
	if err := keys.AddFromURI(ecdsaPK11URI, LoadURI); err != nil {
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
