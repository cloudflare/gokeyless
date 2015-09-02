package client

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless"
)

// Client is a Keyless Client capable of connecting to servers and performing keyless operations.
type Client struct {
	// Config is initialized with the client auth configuration used for communicating with keyless servers.
	Config *tls.Config
	// Dialer used to manage connections.
	Dialer *net.Dialer
	// DefaultServer is a default server to register keys to.
	DefaultServer string
	// m is a Read/Write lock to protect against conccurrent accesses to maps.
	m sync.RWMutex
	// conns maps keyless servers to any open connections to them.
	conns map[string]*gokeyless.Conn
	// allServers maps all known certificate SKIs to their keyless servers.
	allServers map[gokeyless.SKI][]string
}

// NewClient prepares a TLS client capable of connecting to keyservers.
func NewClient(cert tls.Certificate, keyserverCA *x509.CertPool) *Client {
	return &Client{
		Config: &tls.Config{
			RootCAs:      keyserverCA,
			Certificates: []tls.Certificate{cert},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
		},
		Dialer:     &net.Dialer{},
		conns:      make(map[string]*gokeyless.Conn),
		allServers: make(map[gokeyless.SKI][]string),
	}
}

// NewClientFromFile reads certificate, key, and CA files in order to create a Server.
func NewClientFromFile(certFile, keyFile, caFile string) (*Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	pemCerts, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}

	keyserverCA := x509.NewCertPool()
	if !keyserverCA.AppendCertsFromPEM(pemCerts) {
		return nil, errors.New("gokeyless/client: failed to read keyserver CA from PEM")
	}

	return NewClient(cert, keyserverCA), nil
}

// Dial retuns a (reused/reusable) connection to a keyless server.
func (c *Client) Dial(server string) (*gokeyless.Conn, error) {
	if c.Config == nil {
		return nil, errors.New("gokeyless/client: TLS client has not yet been initialized with certificate and keyserver CA")
	}

	c.m.RLock()
	conn, ok := c.conns[server]
	c.m.RUnlock()
	if ok {
		if conn.Use() {
			return conn, nil
		}
		c.m.Lock()
		if c.conns[server] == conn {
			delete(c.conns, server)
		}
		c.m.Unlock()
	}

	log.Debugf("Dialing %s\n", server)
	inner, err := tls.Dial("tcp", server, c.Config)
	if err != nil {
		return nil, err
	}

	c.m.Lock()
	defer c.m.Unlock()
	c.conns[server] = gokeyless.NewConn(inner)
	return c.conns[server], nil
}

// DialAny smartly chooses one of the keyless servers given. (Opting to reuse an existing connection if possible)
func (c *Client) DialAny(ski gokeyless.SKI) (*gokeyless.Conn, error) {
	servers := c.getServers(ski)
	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers registered for SKI %02x", ski)
	}

	for _, server := range servers {
		c.m.RLock()
		conn, ok := c.conns[server]
		c.m.RUnlock()
		if ok {
			if conn.Use() {
				return conn, nil
			}
			c.m.Lock()
			if c.conns[server] == conn {
				delete(c.conns, server)
			}
			c.m.Unlock()
		}
	}

	// choose from possible servers at random until a connection can be established.
	for len(servers) > 0 {
		n := rand.Intn(len(servers))
		conn, err := c.Dial(servers[n])
		if err == nil {
			return conn, nil
		}
		log.Debugf("Couldn't dial server %s: %v", servers[n], err)
		servers = append(servers[:n], servers[n+1:]...)
	}
	return nil, errors.New("couldn't dial any of the registered servers")
}

// getServers returns the keyserver that have been registered with the given SKI.
func (c *Client) getServers(ski gokeyless.SKI) []string {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.allServers[ski]
}

// registerSKI associates the SKI of a public key with a particular keyserver.
func (c *Client) registerSKI(server string, ski gokeyless.SKI) {
	if server == "" {
		server = c.DefaultServer
	}

	log.Debugf("Registering key @ %s with SKI: %02x", server, ski)
	c.m.Lock()
	defer c.m.Unlock()
	c.allServers[ski] = append(c.allServers[ski], server)
}

// RegisterPublicKey SKIs and registers a public key as being held by a server.
func (c *Client) RegisterPublicKey(server string, pub crypto.PublicKey) (*PrivateKey, error) {
	ski, err := gokeyless.GetSKI(pub)
	if err != nil {
		return nil, err
	}
	c.registerSKI(server, ski)

	digest, _ := gokeyless.GetDigest(pub)

	return &PrivateKey{
		public: pub,
		ski:    ski,
		digest: digest,
		client: c,
	}, nil
}

// RegisterCert SKIs the public key contained in a certificate and associates it with a particular keyserver.
func (c *Client) RegisterCert(server string, cert *x509.Certificate) (*PrivateKey, error) {
	return c.RegisterPublicKey(server, cert.PublicKey)
}

var (
	pubkeyExt = regexp.MustCompile(`.+\.pubkey`)
	crtExt    = regexp.MustCompile(`.+\.crt`)
)

// RegisterDir reads all .pubkey and .crt files from a directory and returns associated PublicKey structs.
func (c *Client) RegisterDir(server, dir string, LoadPubKey func([]byte) (crypto.PublicKey, error)) (privkeys []*PrivateKey, err error) {
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		isPubKey := pubkeyExt.MatchString(info.Name())
		isCert := crtExt.MatchString(info.Name())
		if !info.IsDir() && (isPubKey || isCert) {
			log.Infof("Loading %s...\n", path)

			var in []byte
			if in, err = ioutil.ReadFile(path); err != nil {
				return err
			}

			var priv *PrivateKey
			if isPubKey {
				var pub crypto.PublicKey
				if pub, err = LoadPubKey(in); err != nil {
					return err
				}

				if priv, err = c.RegisterPublicKey(server, pub); err != nil {
					return err
				}
			} else {
				var cert *x509.Certificate
				if cert, err = helpers.ParseCertificatePEM(in); err != nil {
					return err
				}

				if priv, err = c.RegisterCert(server, cert); err != nil {
					return err
				}
			}
			privkeys = append(privkeys, priv)
		}
		return nil
	})
	return
}

// LoadTLSCertificate loads a TLS certificate chain from file and registers
// the leaf certificate's public key to the given keyserver.
func (c *Client) LoadTLSCertificate(server, certFile string) (cert tls.Certificate, err error) {
	fail := func(err error) (tls.Certificate, error) { return tls.Certificate{}, err }
	var certPEMBlock []byte
	var certDERBlock *pem.Block

	if certPEMBlock, err = ioutil.ReadFile(certFile); err != nil {
		return fail(err)
	}

	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}

		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}

	if len(cert.Certificate) == 0 {
		return fail(errors.New("crypto/tls: failed to parse certificate PEM data"))
	}

	if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return fail(err)
	}

	cert.PrivateKey, err = c.RegisterCert(server, cert.Leaf)
	if err != nil {
		return fail(err)
	}

	return cert, nil
}
