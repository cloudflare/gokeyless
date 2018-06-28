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
	"log"
	"math/big"
	"sync"
	"testing"
	"time"

	"go4.org/testing/functest"

	"github.com/cloudflare/gokeyless/client"
	"github.com/cloudflare/gokeyless/protocol"
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
	for _, cert := range s.TLSConfig().Certificates {
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
	if testSoftHSM {
		t.Skip("skipping test; SoftHSM2 does not support PKCS1v15")
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
		t.Fatal("rsa decrypt succeeded despite incorrect SessionKeyLen")
	}
}

func TestSeal(t *testing.T) {
	conn, err := remote.Dial(c)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	r := make([]byte, 20)
	if _, err := rand.Read(r); err != nil {
		t.Fatal(err)
	}

	resp, err := conn.DoOperation(protocol.Operation{
		Opcode:  protocol.OpSeal,
		Payload: r,
	})
	if err != nil || resp.Opcode == protocol.OpError {
		t.Fatal(err, resp.GetError())
	} else if !bytes.Equal([]byte("OpSeal "), resp.Payload[:len("OpSeal ")]) {
		t.Fatal("payload type mismatch")
	} else if !bytes.Equal(r, resp.Payload[len("OpSeal "):]) {
		t.Fatal("payload value mismatch")
	}

	resp, err = conn.DoOperation(protocol.Operation{
		Opcode:  protocol.OpUnseal,
		Payload: r,
	})
	if err != nil || resp.Opcode == protocol.OpError {
		t.Fatal(err, resp.GetError())
	} else if !bytes.Equal([]byte("OpUnseal "), resp.Payload[:len("OpUnseal ")]) {
		t.Fatal("payload type mismatch")
	} else if !bytes.Equal(r, resp.Payload[len("OpUnseal "):]) {
		t.Fatal("payload value mismatch")
	}
}

func TestConcurrency(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	conn, err := remote.Dial(c)
	if err != nil {
		t.Fatal(err)
	}

	var err1, err2 error
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		// Make a slow request first.
		start := time.Now()
		_, err := conn.DoOperation(protocol.Operation{
			Opcode:  protocol.OpSeal,
			Payload: []byte("slow"),
		})
		if err != nil {
			err1 = err
		} else if time.Since(start) < time.Second {
			err1 = errors.New("slow request came back too quickly")
		}

		wg.Done()
	}()

	go func() {
		// Make a fast request after a slow request is on the wire.
		time.Sleep(250 * time.Millisecond)

		start := time.Now()
		_, err := conn.DoOperation(protocol.Operation{
			Opcode:  protocol.OpSeal,
			Payload: []byte("fast"),
		})
		if err != nil {
			err2 = err
		} else if time.Since(start) > time.Second {
			// Verify fast request came back before slow request did.
			err2 = errors.New("fast request took too long")
		}

		wg.Done()
	}()

	wg.Wait()
	if err1 != nil || err2 != nil {
		t.Fatalf("err1=%v, err2=%v", err1, err2)
	}
}

func TestRPC(t *testing.T) {
	conn, err := remote.Dial(c)
	if err != nil {
		t.Fatal(err)
	}
	client := conn.RPC()
	defer func() {
		client.Close()
		conn.Close()
	}()

	out := ""
	if err = client.Call("DummyRPC.Append", "Hello", &out); err != nil {
		t.Fatal(err)
	} else if out != "Hello World" {
		t.Fatal("recieved wrong output")
	}

	err = client.Call("DummyRPC.Error", "Hello", &out)
	if err == nil || err.Error() != "remote rpc error" {
		t.Fatal("recieved wrong error")
	}
}
