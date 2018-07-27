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
	"net"
	"net/rpc"
	"sync"
	"testing"
	"time"

	"go4.org/testing/functest"

	"golang.org/x/crypto/ed25519"

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
		} else if ed25519Pub, ok := pub.(ed25519.PublicKey); ok {
			if !ed25519.Verify(ed25519Pub, testEd25519Msg, sig) {
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

// testEd25519Msg is the message that would be signed to produce the
// CertificateVerify message in the TLS 1.3 handshake: see
// https://tlswg.github.io/tls13-spec/draft-ietf-tls-tls13.html#rfc.section.4.4.3.
// TODO(cjpatton) Update this reference once RFC 8446 is published.
var testEd25519Msg = []byte{
	//The header
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20,
	// The context string
	0x54, 0x4c, 0x53, 0x20, 0x31, 0x2e, 0x33, 0x2c, 0x20, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x72, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
	0x61, 0x74, 0x65, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79,
	// The separator
	0x00,
	// The transcript hash
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
}

func TestEd25519Sign(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	if testSoftHSM {
		// TODO(cjpatton) Decide if it's worth adding an Ed25519 test for
		// SoftHSM. If so, then move this test to `TestSign()` above.
		t.Skip("skipping test")
	}

	f := functest.New((*client.PrivateKey).Sign)
	f.Test(t, f.In(ed25519Key, rand.Reader, testEd25519Msg, crypto.Hash(0)).Check(
		checkSignature(ed25519Key.Public(), crypto.Hash(0), false)),
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

func TestKeylessDummyRPC(t *testing.T) {
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

func benchmarkDummyRPC(b *testing.B, requester *rpc.Client) {
	resp := "{"
	if err := requester.Call("DummyRPC.Append", "Hello", &resp); err != nil {
		b.Fatal(err)
	}

	// The barrier is used to ensure that goroutines only start running once we
	// release them.
	var barrier, wg sync.WaitGroup
	barrier.Add(1)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		go func() {
			wg.Add(1)
			barrier.Wait()
			requester.Call("DummyRPC.Append", "Hello", &resp)
			wg.Done()
		}()
	}

	b.ResetTimer()
	barrier.Done()
	wg.Wait()
}

func BenchmarkKeylessDummyRPC(b *testing.B) {
	// Set up RPC client.
	conn, err := remote.Dial(c)
	if err != nil {
		b.Fatal(err)
	}
	requester := conn.RPC()
	defer func() {
		requester.Close()
		conn.Close()
	}()

	benchmarkDummyRPC(b, requester)
}

func BenchmarkDummyRPC(b *testing.B) {
	// Register the dummy RPC.
	dispatcher := rpc.NewServer()
	err := dispatcher.Register(&DummyRPC{})
	if err != nil {
		b.Fatal(err)
	}

	// Set up a TCP socket for the RPC.
	l, err := net.Listen("tcp", ":1234")
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()

	// Listen for and serve a single connection.
	var serr error
	sch := make(chan net.Conn, 1)
	go func() {
		sconn, err := l.Accept()
		if err != nil {
			serr = err
			sch <- nil
			return
		}

		dispatcher.ServeConn(sconn)
		sch <- sconn
	}()

	// Dial the RPC.
	requester, err := rpc.Dial("tcp", "localhost:1234")
	if err != nil {
		b.Fatal(err)
	}
	defer requester.Close()

	benchmarkDummyRPC(b, requester)
}
