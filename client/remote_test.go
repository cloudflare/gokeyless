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

	"github.com/cloudflare/gokeyless"
	"github.com/cloudflare/gokeyless/server"
)

const (
	serverCert   = "testdata/server.pem"
	serverKey    = "testdata/server-key.pem"
	keylessCA    = "testdata/ca.pem"
	serverAddr   = "localhost:0"
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
	s          *server.Server
	c          *Client
	rsaSKI     gokeyless.SKI
	ecdsaSKI   gokeyless.SKI
	remote     Remote
	deadRemote Remote
)

// Set up compatible server and client for use by tests.
func TestMain(m *testing.M) {
	var pemBytes []byte
	var p *pem.Block
	var priv crypto.Signer
	var err error

	// Setup keyless server
	s, err = server.NewServerFromFile(serverCert, serverKey, keylessCA, serverAddr, socketAddr)
	if err != nil {
		log.Fatal(err)
	}

	keys := server.NewDefaultKeystore()
	s.Keys = keys
	pemBytes, err = ioutil.ReadFile(rsaPrivKey)
	if err != nil {
		log.Fatal(err)
	}

	p, _ = pem.Decode(pemBytes)
	priv, err = x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	err = keys.Add(nil, priv)
	if err != nil {
		log.Fatal(err)
	}

	pemBytes, err = ioutil.ReadFile(ecdsaPrivKey)
	if err != nil {
		log.Fatal(err)
	}
	p, _ = pem.Decode(pemBytes)
	priv, err = x509.ParseECPrivateKey(p.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	err = keys.Add(nil, priv)
	if err != nil {
		log.Fatal(err)
	}

	go s.ListenAndServe()

	go s.UnixListenAndServe()

	// wait for server to start
	time.Sleep(100 * time.Millisecond)
	// Setup keyless client
	c, err = NewClientFromFile(clientCert, clientKey, keyserverCA)
	if err != nil {
		log.Fatal(err)
	}
	// set aggressive timeout since all tests use local connections
	c.Dialer.Timeout = 1 * time.Second

	// start a remote server at serverAddr
	host, port, _ := net.SplitHostPort(s.Addr)
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
	err = clientRegisterCertFile(rsaPubKey)
	if err != nil {
		log.Fatal(err)
	}

	err = clientRegisterCertFile(ecdsaPubKey)
	if err != nil {
		log.Fatal(err)
	}

	ret := m.Run()
	s.Close()
	os.Exit(ret)
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

func TestUnixRemote(t *testing.T) {
	r, err := UnixRemote(socketAddr, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	// clear cached remotes and set a unix remote for the client
	c.DefaultRemote = r
	c.remotes = map[gokeyless.SKI]Remote{}

	// register the ECDDSA certificate again with the default remote
	err = clientRegisterCertFile(ecdsaPubKey)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := c.Dial(ecdsaSKI)
	if err != nil {
		t.Fatal(err)
	}

	conn.Close()
}

func TestBadRemote(t *testing.T) {
	// clear cached remotes and set a bad remote for the client
	c.DefaultRemote = deadRemote
	c.remotes = map[gokeyless.SKI]Remote{}

	// register the ECDDSA certificate again with the default broken remote
	err := clientRegisterCertFile(ecdsaPubKey)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.Dial(ecdsaSKI)
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

	g, _ := NewGroup([]Remote{remote, slowRemote})
	c.DefaultRemote = g
	c.remotes = map[gokeyless.SKI]Remote{}
	t.Log("c.DefaultRemote size:", len(c.DefaultRemote.(*Group).remotes))

	// register the ECDDSA certificate again with the default broken remote
	err = clientRegisterCertFile(ecdsaPubKey)
	if err != nil {
		t.Fatal(err)
	}

	// Initially picked a random server
	_, err = c.Dial(ecdsaSKI)
	if err != nil {
		t.Fatal(err)
	}

	g.PingAll(c)

	// After ping checks, 1st remote must be the normal server.
	firstRemote := g.remotes[0]
	conn, err := firstRemote.Dial(c)
	if conn.addr != s.Addr {
		t.Fatal("bad 1st remote addr:", conn.addr)
	}

	// dialing through SKI -> dialing through default remote, should succeed.
	conn, err = c.Dial(ecdsaSKI)
	if err != nil {
		t.Fatal(err)
	}
}

// helper function register a public key from a file.
func clientRegisterCertFile(filepath string) error {
	pemBytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}
	p, _ := pem.Decode(pemBytes)
	pub, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return err
	}
	if _, err = c.RegisterPublicKey("", pub); err != nil {
		return err
	}
	return nil
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
