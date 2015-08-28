package tests

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/client"
)

// RunServerTests load tests a server with a given number of workers and ammount of time.
func RunServerTests(testLen time.Duration, workers int, c *client.Client, server string, privkeys []*client.PrivateKey) {
	log.Infof("Testing %s and %d keys for %v with %d workers...", server, len(privkeys), testLen, workers)

	running := make(chan bool, workers)
	errs := make(chan error)

	for i := 0; i < workers; i++ {
		running <- true
		go func() {
			for range running {
				errs <- testConnect(c, server)

				for _, priv := range privkeys {
					errs <- testKey(priv)
				}

				running <- true
			}
		}()
	}

	timeout := time.After(testLen)
	errCount := 0
	for {
		select {
		case err := <-errs:
			if err != nil {
				log.Error(err)
				errCount++
			}

		case <-timeout:
			close(running)
			log.Infof("Completed with %d errors", errCount)
			return
		}
	}
}

// testConnect tests the ability to Dial and Ping a given server
func testConnect(c *client.Client, server string) error {
	conn, err := c.Dial(server)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Ping(nil)
}

// hashPtxt hashes the plaintext with the given hash algorithm.
func hashPtxt(h crypto.Hash, ptxt []byte) []byte {
	return h.New().Sum(ptxt)[len(ptxt):]
}

// testKey performs and verifies all possible opaque private key operations.
func testKey(priv crypto.Signer) (err error) {
	ptxt := []byte("Test Plaintext")
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

		if sig, err = priv.Sign(r, msg, h); err != nil {
			return
		}

		switch pub := priv.Public().(type) {
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

	if pub, ok := priv.Public().(*rsa.PublicKey); ok {
		var c, m []byte
		if c, err = rsa.EncryptPKCS1v15(r, pub, ptxt); err != nil {
			return
		}

		var decrypter crypto.Decrypter
		if decrypter, ok = priv.(crypto.Decrypter); !ok {
			return errors.New("rsa public key but cannot decrypt")
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
	}

	return nil
}
