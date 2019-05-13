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
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"

	"github.com/cloudflare/gokeyless/client"
	"github.com/cloudflare/gokeyless/protocol"
)

func (s *IntegrationTestSuite) TestConnect() {
	require := require.New(s.T())

	if testing.Short() {
		s.T().SkipNow()
	}

	conn, err := s.remote.Dial(s.client)
	require.NoError(err)
	defer conn.Close()

	err = conn.Ping([]byte("Hello!"))
	require.NoError(err)
}

func (s *IntegrationTestSuite) TestBlacklist() {
	require := require.New(s.T())

	// create a new client with blacklist
	blc, err := client.NewClientFromFile(clientCert, clientKey, keyserverCA)
	require.NoError(err)
	require.NotNil(blc)

	blc.ClearBlacklist()
	// add server certificate to blacklist
	for _, cert := range s.server.TLSConfig().Certificates {
		if cert.Leaf == nil {
			require.False(len(cert.Certificate) == 0, "invalid server certificate")
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			require.NoError(err)
			cert.Leaf = leaf
		}
		blc.PopulateBlacklistFromCert(cert.Leaf, s.serverPort)
	}

	_, err = s.remote.Dial(blc)
	require.Error(err, "was able to dial blacklisted server")
}

var ptxt = []byte("Hello!")

func hashMsg(h crypto.Hash) []byte {
	msgHash := h.New()
	msgHash.Write(ptxt)
	return msgHash.Sum(nil)
}

func checkSignature(pub crypto.PublicKey, h crypto.Hash, sig []byte) error {
	if rsaPub, ok := pub.(*rsa.PublicKey); ok {
		return rsa.VerifyPKCS1v15(rsaPub, h, hashMsg(h), sig)
	}

	if ecdsaPub, ok := pub.(*ecdsa.PublicKey); ok {
		ecdsaSig := new(struct{ R, S *big.Int })
		asn1.Unmarshal(sig, ecdsaSig)
		if !ecdsa.Verify(ecdsaPub, hashMsg(h), ecdsaSig.R, ecdsaSig.S) {
			return errors.New("failed to verify")
		}
		return nil
	}

	if ed25519Pub, ok := pub.(ed25519.PublicKey); ok {
		if !ed25519.Verify(ed25519Pub, testEd25519Msg, sig) {
			return errors.New("failed to verify")
		}
		return nil
	}

	return fmt.Errorf("unknown public key type: %v", pub)
}

func (s *IntegrationTestSuite) TestSign() {
	if testing.Short() {
		s.T().SkipNow()
	}

	tests := []struct {
		name string
		s    crypto.Signer
		h    crypto.Hash
	}{
		{"rsa-SHA1", s.rsaKey, crypto.SHA1},
		{"rsa-SHA256", s.rsaKey, crypto.SHA256},
		{"rsa-SHA384", s.rsaKey, crypto.SHA384},
		{"rsa-SHA512", s.rsaKey, crypto.SHA512},
		{"ecdsa-SHA1", s.ecdsaKey, crypto.SHA1},
		{"ecdsa-SHA256", s.ecdsaKey, crypto.SHA256},
		{"ecdsa-SHA384", s.ecdsaKey, crypto.SHA384},
		{"ecdsa-SHA512", s.ecdsaKey, crypto.SHA512},
	}
	for _, test := range tests {
		s.T().Run(test.name, func(t *testing.T) {
			require := require.New(t)

			b, err := test.s.Sign(rand.Reader, hashMsg(test.h), test.h)
			require.NoError(err)
			require.NoError(checkSignature(test.s.Public(), test.h, b))
		})
	}
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

func (s *IntegrationTestSuite) TestEd25519Sign() {
	require := require.New(s.T())

	if testing.Short() {
		s.T().SkipNow()
	}
	if testSoftHSM {
		// TODO(cjpatton) Decide if it's worth adding an Ed25519 test for
		// SoftHSM. If so, then move this test to `TestSign()` above.
		s.T().Skip("skipping test")
	}

	b, err := s.ed25519Key.Sign(rand.Reader, testEd25519Msg, crypto.Hash(0))
	require.NoError(err)
	require.NoError(checkSignature(s.ed25519Key.Public(), crypto.Hash(0), b))
}

func (s *IntegrationTestSuite) TestRSADecrypt() {
	require := require.New(s.T())

	if testing.Short() {
		s.T().SkipNow()
	}
	if testSoftHSM {
		s.T().Skip("skipping test; SoftHSM2 does not support PKCS1v15")
	}

	pub, ok := s.rsaKey.Public().(*rsa.PublicKey)
	require.True(ok, "couldn't use public key as RSA key")

	c, err := rsa.EncryptPKCS1v15(rand.Reader, pub, ptxt)
	require.NoError(err)

	m, err := s.rsaKey.Decrypt(rand.Reader, c, &rsa.PKCS1v15DecryptOptions{})
	require.NoError(err)
	require.Equal(0, bytes.Compare(ptxt, m), fmt.Sprintf("rsa decrypt failed m: %dB\tptxt: %dB", len(m), len(ptxt)))

	m, err = s.rsaKey.Decrypt(rand.Reader, c, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: len(ptxt)})
	require.NoError(err)
	require.Equal(0, bytes.Compare(ptxt, m), fmt.Sprintf("rsa decrypt failed m: %dB\tptxt: %dB", len(m), len(ptxt)))

	m, err = s.rsaKey.Decrypt(rand.Reader, c, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: len(ptxt) + 1})
	require.NoError(err)
	require.NotEqual(0, bytes.Compare(ptxt, m), fmt.Sprintf("rsa decrypt succeeded despite incorrect SessionKeyLen m: %dB\tptxt: %dB", len(m), len(ptxt)))
}

func (s *IntegrationTestSuite) TestSeal() {
	require := require.New(s.T())

	conn, err := s.remote.Dial(s.client)
	require.NoError(err)
	defer conn.Close()

	r := make([]byte, 20)
	_, err = rand.Read(r)
	require.NoError(err)

	resp, err := conn.DoOperation(protocol.Operation{
		Opcode:  protocol.OpSeal,
		Payload: r,
	})
	require.NoError(err)
	require.NotEqual(protocol.OpError, resp.Opcode, resp.GetError())
	require.True(bytes.Equal([]byte("OpSeal "), resp.Payload[:len("OpSeal ")]), "payload type mismatch")
	require.True(bytes.Equal(r, resp.Payload[len("OpSeal "):]), "payload value mismatch")

	resp, err = conn.DoOperation(protocol.Operation{
		Opcode:  protocol.OpUnseal,
		Payload: r,
	})
	require.NoError(err)
	require.NotEqual(protocol.OpError, resp.Opcode, resp.GetError())
	require.True(bytes.Equal([]byte("OpUnseal "), resp.Payload[:len("OpUnseal ")]), "payload type mismatch")
	require.True(bytes.Equal(r, resp.Payload[len("OpUnseal "):]), "payload value mismatch")
}

func (s *IntegrationTestSuite) TestUndefinedCustomOp() {
	require := require.New(s.T())

	conn, err := s.remote.Dial(s.client)
	require.NoError(err)
	defer conn.Close()

	resp, err := conn.DoOperation(protocol.Operation{
		Opcode:         protocol.OpCustom,
		CustomFuncName: "undefined",
	})
	require.NoError(err)
	require.Equal(protocol.OpError, resp.Opcode, resp.GetError())
}

func (s *IntegrationTestSuite) TestConcurrency() {
	require := require.New(s.T())

	if testing.Short() {
		s.T().SkipNow()
	}

	// Here we explicitly want to test connection multiplexing.
	atomic.StoreUint32(&client.TestDisableConnectionPool, 0)

	conn, err := s.remote.Dial(s.client)
	require.NoError(err)
	defer conn.Close()

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
	require.NoError(err1)
	require.NoError(err2)
}

func (s *IntegrationTestSuite) TestRPC() {
	require := require.New(s.T())

	conn, err := s.remote.Dial(s.client)
	require.NoError(err)
	defer conn.Close()

	client := conn.RPC()
	defer func() {
		client.Close()
		conn.Close()
	}()

	var out string
	err = client.Call("DummyRPC.Append", "Hello", &out)
	require.NoError(err)
	require.Equal("Hello World", out)

	err = client.Call("DummyRPC.Error", "Hello", &out)
	require.Error(err)
	require.Equal("remote rpc error", err.Error())
	require.Equal("Hello World", out)
}

func (s *IntegrationTestSuite) TestShutdown() {
	require := require.New(s.T())

	// The idea here is to spawn a bunch of goroutines which keep making new
	// connections to the server, and then ask the server to shutdown and
	// confirm it doesn't hang. The connection tracking logic is a bit hairy, so
	// we rely on this test and the race detector to help ensure correctness.
	const n = 25
	wg := sync.WaitGroup{}
	wg.Add(n)
	wg2 := sync.WaitGroup{}
	wg2.Add(n)
	done := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			wg.Done()
			defer wg2.Done()

			// Continuously spawn new connections without closing them.
			for {
				select {
				case <-done:
					return
				default:
				}
				// Errors don't phase us, we're just trying to generate load.
				s.remote.Dial(s.client)
			}
		}()
	}

	wg.Wait()
	time.Sleep(100 * time.Millisecond)

	err := shutdownServer(s.server, 15*time.Second)

	// Dump the stacks of running goroutines if we're about to fail.
	if err != nil {
		buf := make([]byte, 1<<20)
		runtime.Stack(buf, true)
		fmt.Printf("%s\n", buf)
	}

	close(done) // stop spawning connections
	wg2.Wait()

	// Let TearDownTest know we've already closed it.
	s.server = nil

	require.NoError(err)
}
