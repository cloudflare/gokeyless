package client

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net"
	"testing"
	"time"

	"github.com/cloudflare/gokeyless"
	"github.com/cloudflare/gokeyless/server"
)

const (
	serverCert   = "testdata/server.pem"
	serverKey    = "testdata/server-key.pem"
	keylessCA    = "testdata/ca.pem"
	serverAddr   = "localhost:0"
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

	go func() {
		if err := s.ListenAndServe(); err != nil {
			t.Fatal(err)
		}
	}()

	// wait for server to start
	time.Sleep(100 * time.Millisecond)
	// Setup keyless client
	if c, err = NewClientFromFile(clientCert, clientKey, keyserverCA); err != nil {
		t.Fatal(err)
	}

	// start a remote server at serverAddr
	host, port, _ := net.SplitHostPort(s.Addr)
	remote, err = c.LookupServerWithName("localhost", host, port)
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
	registerCertFile(rsaPubKey, t)

	registerCertFile(ecdsaPubKey, t)

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
	registerCertFile(ecdsaPubKey, t)

	_, err := c.Dial(ecdsaSKI)
	if err == nil {
		t.Fatal("bad remote management")
	}
}

func TestSlowServer(t *testing.T) {
	// Setup a slow keyless server
	s2, err := server.NewServerFromFile(serverCert, serverKey, keylessCA,
		serverAddr, serverAddr)
	if err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", serverAddr)
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
	host, p, _ := net.SplitHostPort(s.Addr)
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

	c.DefaultRemote = remote.Add(slowRemote)
	c.servers = map[string]Remote{}
	c.remotes = map[gokeyless.SKI]Remote{}
	t.Log("c.DefaultRemote size:", len(c.DefaultRemote.(*Group).remotes))

	// register the ECDDSA certificate again with the default broken remote
	registerCertFile(ecdsaPubKey, t)

	// Initially picked a random server
	_, err = c.Dial(ecdsaSKI)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(200 * time.Millisecond)

	// After a few health checks, must pick the normal server
	conn, err := c.Dial(ecdsaSKI)
	if err != nil {
		t.Fatal(err)
	}
	if conn.addr != s.Addr {
		t.Fatal("bad remote addr:", conn.addr)
	}
}

// helper function register a public key from a file.
func registerCertFile(filepath string, t *testing.T) {
	pemBytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pem.Decode(pemBytes)
	pub, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.RegisterPublicKey("", pub); err != nil {
		t.Fatal(err)
	}
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
