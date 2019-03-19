package client

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
	"github.com/cloudflare/gokeyless/server"
)

const (
	serverCert   = "testdata/server.pem"
	serverKey    = "testdata/server-key.pem"
	keylessCA    = "testdata/ca.pem"
	socketAddr   = "/tmp/keyless.socket"
	rsaPrivKey   = "testdata/rsa.key"
	ecdsaPrivKey = "testdata/ecdsa.key"

	clientCert  = "testdata/client.pem"
	clientKey   = "testdata/client-key.pem"
	keyserverCA = "testdata/ca.pem"
	rsaPubKey   = "testdata/rsa.pubkey"
	ecdsaPubKey = "testdata/ecdsa.pubkey"
)

var (
	// the address that s is listening on
	sAddr       string
	s           *server.Server
	c           *Client
	rsaSigner   crypto.Signer
	ecdsaSigner crypto.Signer
	remote      Remote
	deadRemote  Remote
)

func fixedCurrentTime() time.Time {
	// Fixed time where certificates are still valid.
	return time.Date(2019, time.March, 1, 0, 0, 0, 0, time.UTC)
}

// LoadKey attempts to load a private key from PEM or DER.
func LoadKey(in []byte) (priv crypto.Signer, err error) {
	priv, err = helpers.ParsePrivateKeyPEM(in)
	if err == nil {
		return priv, nil
	}

	return derhelpers.ParsePrivateKeyDER(in)
}

// Set up compatible server and client for use by tests.
func TestMain(m *testing.M) {
	var err error
	// Setup keyless server
	s, err = server.NewServerFromFile(nil, serverCert, serverKey, keylessCA)
	if err != nil {
		log.Fatal(err)
	}
	s.TLSConfig().Time = fixedCurrentTime

	keys, err := server.NewKeystoreFromDir("testdata", LoadKey)
	if err != nil {
		log.Fatal(err)
	}
	s.SetKeystore(keys)

	tcpListener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatal(err)
	}
	sAddr = tcpListener.Addr().String()

	unixListener, err := net.Listen("unix", socketAddr)
	if err != nil {
		log.Fatal(err)
	}

	go s.Serve(tcpListener)
	go s.Serve(unixListener)

	// wait for server to start
	time.Sleep(time.Second)
	// Setup keyless client
	c, err = NewClientFromFile(clientCert, clientKey, keyserverCA)
	if err != nil {
		log.Fatal(err)
	}
	c.Config.Time = fixedCurrentTime
	// set aggressive timeout since all tests use local connections
	c.Dialer.Timeout = 3 * time.Second

	// start a remote server at serverAddr
	host, port, _ := net.SplitHostPort(sAddr)
	remote, err = c.LookupServerWithName("localhost", host, port)
	if err != nil {
		log.Fatal(err)
	}

	deadRemote, err = c.LookupServer("localhost:65432")
	if err != nil {
		log.Fatal(err)
	}

	// Make a remote group containing a good server and a bad one.
	// Setup default remote to be the above group
	c.DefaultRemote, err = NewGroup([]Remote{remote, deadRemote})
	if err != nil {
		log.Fatal(err)
	}

	// register both public keys with empty remote server so
	// DefaultRemote will be used
	rsaSigner, err = NewRemoteSignerByCertFile(rsaPubKey)
	if err != nil {
		log.Fatal(err)
	}

	ecdsaSigner, err = NewRemoteSignerByCertFile(ecdsaPubKey)
	if err != nil {
		log.Fatal(err)
	}

	ret := m.Run()
	s.Close()
	os.Exit(ret)
}

func TestRemoteGroup(t *testing.T) {
	r, err := c.getRemote("")
	if err != nil {
		t.Fatal(err)
	}

	_, err = r.Dial(c)
	if err != nil {
		t.Fatal(err)
	}

	// defqult remote group has one working remote and one that doesn't.
	// PingAll should not hang.
	r.PingAll(c, 1)
	r.PingAll(c, 2)
	r.PingAll(c, 3)
}

func TestUnixRemote(t *testing.T) {
	r, err := UnixRemote(socketAddr, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	// clear cached remotes and set a unix remote for the client
	c.DefaultRemote = r

	conn, err := r.Dial(c)
	if err != nil {
		t.Fatal(err)
	}

	conn.Close()
}

func TestBadRemote(t *testing.T) {
	// clear cached remotes and set a bad remote for the client
	c.DefaultRemote = deadRemote

	_, err := deadRemote.Dial(c)
	if err == nil {
		t.Fatal("dialing bad remote should fail.")
	}
}

func TestSlowServer(t *testing.T) {
	// Setup a slow keyless server
	cfg := server.DefaultServeConfig().WithTCPTimeout(time.Second * 30)
	s2, err := server.NewServerFromFile(cfg, serverCert, serverKey, keylessCA)
	if err != nil {
		t.Fatal(err)
	}
	s2.TLSConfig().Time = fixedCurrentTime

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	sl := slowListener{l}

	go func() {
		if err := s2.Serve(&sl); err != nil {
			t.Fatal(err)
		}
	}()

	// wait for server to come up
	time.Sleep(100 * time.Millisecond)

	// clear cached remotes and set a remote group of normal and slow servers
	host, p, _ := net.SplitHostPort(sAddr)
	remote, err = c.LookupServerWithName("localhost", host, p)
	if err != nil {
		t.Fatal(err)
	}

	s2host, s2port, _ := net.SplitHostPort(sl.Addr().String())
	slowRemote, err := c.LookupServerWithName("localhost", s2host, s2port)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("slow server is at %s:%s", s2host, s2port)

	g, _ := NewGroup([]Remote{remote, slowRemote})
	c.DefaultRemote = g
	t.Log("c.DefaultRemote size:", len(c.DefaultRemote.(*Group).remotes))

	g.PingAll(c, 1)

	// After ping checks, 1st remote must be the normal server.
	firstRemote := g.remotes[0]
	conn, err := firstRemote.Dial(c)
	if err != nil {
		t.Fatal(err)
	}
	if conn.addr != sAddr {
		t.Fatal("bad 1st remote addr:", conn.addr)
	}
}

// helper function reads a cert from a file and convert it to a signer
func NewRemoteSignerByCertFile(filepath string) (crypto.Signer, error) {
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

// slowListener returns a slowConn
type slowListener struct {
	l net.Listener
}

// slowConn slows down each read and write by 10 ms.
type slowConn struct {
	c net.Conn
}

func (sl *slowListener) Accept() (net.Conn, error) {
	c, err := sl.l.Accept()
	if err != nil {
		return nil, err
	}
	return &slowConn{c}, nil
}

func (sl *slowListener) Close() error {
	return sl.l.Close()
}

func (sl *slowListener) Addr() net.Addr {
	return sl.l.Addr()
}

func (sc *slowConn) Read(b []byte) (n int, err error) {
	time.Sleep(10 * time.Millisecond)
	return sc.c.Read(b)
}

func (sc *slowConn) Write(b []byte) (n int, err error) {
	time.Sleep(10 * time.Millisecond)
	return sc.c.Write(b)
}

func (sc *slowConn) Close() error {
	return sc.c.Close()
}

func (sc *slowConn) LocalAddr() net.Addr {
	return sc.c.LocalAddr()
}

func (sc *slowConn) RemoteAddr() net.Addr {
	return sc.c.RemoteAddr()
}

func (sc *slowConn) SetDeadline(t time.Time) error {
	return sc.c.SetDeadline(t)
}

func (sc *slowConn) SetReadDeadline(t time.Time) error {
	return sc.c.SetReadDeadline(t)
}

func (sc *slowConn) SetWriteDeadline(t time.Time) error {
	return sc.c.SetWriteDeadline(t)
}
