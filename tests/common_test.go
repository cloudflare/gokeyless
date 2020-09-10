package tests

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/cloudflare/cfssl/helpers/derhelpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/client"
	"github.com/cloudflare/gokeyless/internal/test/params"
	"github.com/cloudflare/gokeyless/protocol"
	"github.com/cloudflare/gokeyless/server"
)

const (
	serverCert     = "testdata/server.pem"
	serverKey      = "testdata/server-key.pem"
	keylessCA      = "testdata/ca.pem"
	rsaPrivKey     = "testdata/rsa.key"
	ecdsaPrivKey   = "testdata/ecdsa.key"
	ed25519PrivKey = "testdata/ed25519.key"

	clientCert    = "testdata/client.pem"
	clientKey     = "testdata/client-key.pem"
	keyserverCA   = "testdata/ca.pem"
	rsaPubKey     = "testdata/rsa.pubkey"
	ecdsaPubKey   = "testdata/ecdsa.pubkey"
	ed25519PubKey = "testdata/ed25519.pubkey"
)

func init() {
	flag.BoolVar(&testSoftHSM, "softhsm2", false, "whether to test against SoftHSM2")
	flag.IntVar(&log.Level, "loglevel", log.LevelFatal, "Log level (0 = DEBUG, 5 = FATAL)")
}

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

type IntegrationTestSuite struct {
	suite.Suite

	serverPort int
	serverAddr string
	server     *server.Server
	client     *client.Client
	rsaKey     *client.Decrypter
	ecdsaKey   *client.PrivateKey
	ed25519Key *client.PrivateKey
	remote     client.Remote
}

func fixedCurrentTime() time.Time {
	// Fixed time where certificates are still valid.
	return time.Date(2019, time.March, 1, 0, 0, 0, 0, time.UTC)
}

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
func (s *IntegrationTestSuite) NewRemoteSignerByPubKeyFile(filepath string) (crypto.Signer, error) {
	pemBytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(pemBytes)
	pub, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		pub, err = derhelpers.ParseEd25519PublicKey(p.Bytes)
		if err != nil {
			return nil, err
		}
	}
	return s.client.NewRemoteSignerByPublicKey(context.Background(), "", pub)
}

func TestSuite(t *testing.T) {
	s := &IntegrationTestSuite{}
	suite.Run(t, s)
}

// SetupTest sets up a compatible server and client for use by tests.
func (s *IntegrationTestSuite) SetupTest() {
	require := require.New(s.T())

	// By default we want to exercise the connection management code as much as
	// possible, so we disable connection multiplexing. Individual tests can
	// change this as necessary.
	atomic.StoreUint32(&client.TestDisableConnectionPool, 1)

	var err error
	s.server, err = server.NewServerFromFile(nil, serverCert, serverKey, keylessCA)
	require.NoError(err)
	s.server.TLSConfig().Time = fixedCurrentTime

	if !testSoftHSM {
		keys, err := server.NewKeystoreFromDir("testdata", server.DefaultLoadKey)
		require.NoError(err)
		s.server.SetKeystore(keys)
	} else {
		keys := server.NewDefaultKeystore()
		err = keys.AddFromURI(params.RSAURI, loadURI)
		require.NoError(err)
		err = keys.AddFromURI(params.ECDSAURI, loadURI)
		require.NoError(err)
		s.server.SetKeystore(keys)
	}

	s.server.SetSealer(dummySealer{})
	err = s.server.RegisterRPC(DummyRPC{})
	require.NoError(err)

	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0") // let the OS assign a random port
	require.NoError(err)
	l, err := net.ListenTCP("tcp", addr)
	require.NoError(err)
	s.serverPort = l.Addr().(*net.TCPAddr).Port
	s.serverAddr = fmt.Sprintf("localhost:%d", s.serverPort)

	listening := make(chan bool)
	go func() {
		listening <- true
		s.server.Serve(l)
	}()
	<-listening

	s.client, err = client.NewClientFromFile(clientCert, clientKey, keyserverCA)
	require.NoError(err)
	s.client.Config.Time = fixedCurrentTime

	// Specify 127.0.0.1 rather than localhost since we don't listen on IPv6.
	s.remote, err = s.client.LookupServerWithName("localhost", "127.0.0.1", strconv.Itoa(s.serverPort))
	require.NoError(err)
	s.client.DefaultRemote = s.remote

	var ok bool
	privKey, err := s.NewRemoteSignerByPubKeyFile(rsaPubKey)
	require.NoError(err)
	s.rsaKey, ok = privKey.(*client.Decrypter)
	require.True(ok, "bad RSA key registration")

	privKey, err = s.NewRemoteSignerByPubKeyFile(ecdsaPubKey)
	require.NoError(err)
	s.ecdsaKey, ok = privKey.(*client.PrivateKey)
	require.True(ok, "bad ECDSA key registration")

	privKey, err = s.NewRemoteSignerByPubKeyFile(ed25519PubKey)
	require.NoError(err)
	s.ed25519Key, ok = privKey.(*client.PrivateKey)
	require.True(ok, "bad Ed25519 key registration")
}

func (s *IntegrationTestSuite) TearDownTest() {
	require := require.New(s.T())

	if s.server != nil {
		err := shutdownServer(s.server, 2*time.Second)
		require.NoError(err)
	}

	atomic.StoreUint32(&client.TestDisableConnectionPool, 0)
}

func shutdownServer(server *server.Server, timeout time.Duration) error {
	closed := make(chan error)
	go func() {
		closed <- server.Close()
	}()
	select {
	case err := <-closed:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("timed out waiting for Close() after %v", timeout)
	}
}

func (s *IntegrationTestSuite) TearDownSuite() {
	atomic.StoreUint32(&client.TestDisableConnectionPool, 0)
}
