package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"

	"github.com/cloudflare/gokeyless"
)

// Client is a Keyless Client capable of connecting to servers and performing keyless operations.
type Client struct {
	// Config is initialized with the client auth configuration used for communicating with keyless servers.
	Config *tls.Config
	Dialer *net.Dialer
	// conns maps keyless servers to any open connections to them.
	conns map[string]*gokeyless.Conn
	// allServers maps all known certificate digests to keyless server on which it can be found
	allServers map[gokeyless.Digest][]string
}

// NewClient prepares a TLS client capable of connecting to keyservers.
func NewClient(certFile, keyFile, caFile string) (*Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	pemCerts, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}

	keyserverRoot := x509.NewCertPool()
	if !keyserverRoot.AppendCertsFromPEM(pemCerts) {
		return nil, errors.New("gokeyless/client: failed to read keyserver CA from PEM")
	}

	return &Client{
		Config: &tls.Config{
			RootCAs:      keyserverRoot,
			Certificates: []tls.Certificate{cert},
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		},
		Dialer:     &net.Dialer{},
		conns:      make(map[string]*gokeyless.Conn),
		allServers: make(map[gokeyless.Digest][]string),
	}, nil
}

// Dial retuns a (reused/reusable) connection to a keyless server.
func (c *Client) Dial(server string) (*gokeyless.Conn, error) {
	if c.Config == nil {
		return nil, errors.New("gokeyless/client: TLS client has not yet been initialized with certificate and keyserver CA")
	}

	if conn, ok := c.conns[server]; ok && conn.IsOpen {
		return conn, nil
	} else if ok {
		delete(c.conns, server)
	}

	log.Printf("Dialing server: %s\n", server)
	conn, err := tls.Dial("tcp", server, c.Config)
	if err != nil {
		return nil, err
	}

	c.conns[server] = gokeyless.NewConn(conn)
	return c.conns[server], nil
}

// DialAny smartly chooses one of the keyless servers given. (Opting to reuse an existing connection if possible)
func (c *Client) DialAny(dgst gokeyless.Digest) (*gokeyless.Conn, error) {
	servers := c.allServers[dgst]
	if len(servers) == 0 {
		return nil, errors.New("no servers given")
	}

	var existing []*gokeyless.Conn
	for _, server := range servers {
		if conn, ok := c.conns[server]; ok {
			existing = append(existing, conn)
		}
	}
	// choose from existing connections at random
	if len(existing) > 0 {
		return existing[rand.Intn(len(existing))], nil
	}

	// choose from possible servers at random until a connection can be established.
	for len(servers) > 0 {
		n := rand.Intn(len(servers))
		conn, err := c.Dial(servers[n])
		if err == nil {
			return conn, nil
		}
		log.Printf("Couldn't dial server %s: %v", servers[n], err)
		servers = append(servers[:n], servers[n+1:]...)
	}
	return nil, errors.New("couldn't dial any of the servers given")
}

// RegisterDigest associates the digest of a public key with a particular keyserver.
func (c *Client) RegisterDigest(server string, dgst gokeyless.Digest) {
	c.allServers[dgst] = append(c.allServers[dgst], server)
}

// RegisterPublicKey digests and registers a public key as being held by a server.
func (c *Client) RegisterPublicKey(server string, pub crypto.PublicKey) (*PrivateKey, error) {
	var dgst gokeyless.Digest
	switch pkey := pub.(type) {
	case *rsa.PublicKey:
		dgst = sha256.Sum256([]byte(fmt.Sprintf("%X", pkey.N)))
	case *ecdsa.PublicKey:
		// TODO: this should be consistent with the keyserver, and hopefully SKI...
		dgst = sha256.Sum256(append(pkey.X.Bytes(), pkey.Y.Bytes()...))
	default:
		return nil, errors.New("certificate contains unknown public key type")
	}
	c.RegisterDigest(server, dgst)

	return &PrivateKey{
		public: pub,
		dgst:   dgst,
		client: c,
	}, nil
}

// RegisterCert digests the public key contained in a certificate and associates it with a particular keyserver.
func (c *Client) RegisterCert(server string, cert *x509.Certificate) (*PrivateKey, error) {
	return c.RegisterPublicKey(server, cert.PublicKey)
}
