package client

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
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
	// Resolvers is an ordered list of DNS servers used to look up remote servers.
	Resolvers []string
	// DefaultRemote is a default remote to dial and register keys to.
	DefaultRemote Remote
	// Blacklist is a list of addresses that this client won't dial.
	Blacklist AddrSet
	// m is a Read/Write lock to protect against conccurrent accesses to maps.
	m sync.RWMutex
	// servers maps all known server names to their servers.
	servers map[string]Remote
	// remotes maps all known certificate SKIs to their Remote.
	remotes map[gokeyless.SKI]Remote
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
		Dialer:    &net.Dialer{},
		Blacklist: make(AddrSet),
		servers:   make(map[string]Remote),
		remotes:   make(map[gokeyless.SKI]Remote),
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

// An AddrSet is a set of addresses.
type AddrSet map[string]bool

// Add adds an addr to the set of addresses.
func (as AddrSet) Add(addr net.Addr) {
	as[addr.String()] = true
}

// Contains determines if an addr belongs to the set of addresses.
func (as AddrSet) Contains(addr net.Addr) bool {
	contains, ok := as[addr.String()]
	return ok && contains
}

// PopulateBlacklist populates the client blacklist using an x509 certificate.
func (c *Client) PopulateBlacklist(cert *x509.Certificate, port int) {
	for _, ip := range cert.IPAddresses {
		c.Blacklist.Add(&net.TCPAddr{
			IP:   ip,
			Port: port,
		})
	}
	for _, host := range cert.DNSNames {
		if ips, err := net.LookupIP(host); err == nil {
			for _, ip := range ips {
				c.Blacklist.Add(&net.TCPAddr{
					IP:   ip,
					Port: port,
				})
			}
		}
	}
}

// ClearBlacklist empties the client blacklist
func (c *Client) ClearBlacklist() {
	c.Blacklist = make(AddrSet)
}

// Dial smartly establishes a connection to a registered keyless server
// or reuses an existing connection if possible.
func (c *Client) Dial(ski gokeyless.SKI) (*Conn, error) {
	c.m.RLock()
	r, ok := c.remotes[ski]
	c.m.RUnlock()
	if !ok {
		if c.DefaultRemote == nil {
			return nil, fmt.Errorf("no servers registered for SKI %02x", ski)
		}

		r = c.DefaultRemote
	}
	return r.Dial(c)
}

// ActivateServer dials a server and sends an activation request.
func (c *Client) ActivateServer(server string, token []byte) error {
	r, err := c.LookupServer(server)
	if err != nil {
		return err
	}

	conn, err := r.Dial(c)
	if err != nil {
		return err
	}
	defer conn.Close()

	return conn.Activate(token)
}

// AddRemote adds a remote for the given SKI, optionally registering it
// under the given server name.
func (c *Client) AddRemote(server string, r Remote, ski gokeyless.SKI) {
	c.m.Lock()
	defer c.m.Unlock()

	if server != "" {
		if oldServer, ok := c.servers[server]; ok {
			oldServer.Add(r)
		} else {
			c.servers[server] = r
		}
	}

	if oldRemote, ok := c.remotes[ski]; ok {
		oldRemote.Add(r)
	} else {
		c.remotes[ski] = r
	}
}

// registerSKI associates the SKI of a public key with a particular keyserver.
func (c *Client) registerSKI(server string, ski gokeyless.SKI) (err error) {
	log.Debugf("Registering key @ %s with SKI: %02x", server, ski)
	var r Remote
	if server == "" {
		r = c.DefaultRemote
		if r == nil {
			err = errors.New("no default remote")
			log.Error(err)
			return
		}
	} else {
		var ok bool
		c.m.RLock()
		r, ok = c.servers[server]
		c.m.RUnlock()
		if ok {
			server = ""
		} else {
			if r, err = c.LookupServer(server); err != nil {
				return
			}
		}
	}

	c.AddRemote(server, r, ski)
	return
}

// RegisterPublicKeyTemplate registers a public key with additional operation template information.
func (c *Client) RegisterPublicKeyTemplate(server string, pub crypto.PublicKey, sni string, serverIP net.IP) (*PrivateKey, error) {
	ski, err := gokeyless.GetSKI(pub)
	if err != nil {
		return nil, err
	}

	if err := c.registerSKI(server, ski); err != nil {
		return nil, err
	}

	digest, _ := gokeyless.GetDigest(pub)

	return &PrivateKey{
		public:   pub,
		client:   c,
		ski:      ski,
		digest:   digest,
		sni:      sni,
		serverIP: serverIP,
	}, nil
}

// RegisterPublicKey SKIs and registers a public key as being held by a server.
func (c *Client) RegisterPublicKey(server string, pub crypto.PublicKey) (*PrivateKey, error) {
	return c.RegisterPublicKeyTemplate(server, pub, "", nil)
}

// RegisterCert SKIs the public key contained in a certificate and associates it with a particular keyserver.
func (c *Client) RegisterCert(server string, cert *x509.Certificate) (*PrivateKey, error) {
	return c.RegisterPublicKeyTemplate(server, cert.PublicKey, "", nil)
}

// RegisterCertPEM registers a single PEM cert (possibly the leaf of a chain of certs).
func (c *Client) RegisterCertPEM(server string, certsPEM []byte) (*PrivateKey, error) {
	block, _ := pem.Decode(certsPEM)
	if block == nil {
		return nil, errors.New("couldn't parse PEM bytes")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return c.RegisterPublicKeyTemplate(server, cert.PublicKey, "", nil)
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

				if priv, err = c.RegisterPublicKeyTemplate(server, pub, "", nil); err != nil {
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

type sigAlgSort func(clientHello *tls.ClientHelloInfo) gokeyless.SigAlgs

func defaultSigAlgs(clientHello *tls.ClientHelloInfo) gokeyless.SigAlgs {
	// ECDSA SHA-384, ECDSA SHA-256, RSA SHA-384, RSA SHA-256, RSA SHA-1
	return []byte{0x04, 0x03, 0x05, 0x03, 0x01, 0x05, 0x01, 0x04, 0x01, 0x02}
}

// NewGetCertificate fetches a crypto/tls GetCertificate function from server using
// a clientHello to sigAlgs translation function
func (c *Client) NewGetCertificate(sigAlgSort sigAlgSort, server string) (func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error), error) {
	if sigAlgSort == nil {
		sigAlgSort = defaultSigAlgs
	}

	return func(hello *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
		var certDERBlock *pem.Block

		cert = new(tls.Certificate)
		sigAlgs := sigAlgSort(hello)

		// Pick the correct remote
		remote, ok := c.servers[server]
		if !ok {
			remote = c.DefaultRemote
		}
		if remote == nil {
			return nil, errors.New("no remote servers")
		}

		conn, err := remote.Dial(c)
		if err != nil {
			return nil, errors.New("unable to contact remote server")
		}

		// NOTE: there is no way to get ServerIP out of the client hello,
		// so we don't use it for GetCertificate. If the intention is to provide
		// different certificates for different IPs, this will not work.
		// Only SNI-based indexing is possible in tls.GetCertificate.
		certPEMBlock, err := conn.GetCertificate(sigAlgs, nil, hello.ServerName)
		if err != nil {
			return nil, errors.New("no matching certificate found")
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
			return nil, errors.New("crypto/tls: failed to parse certificate PEM data")
		}

		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, err
		}

		priv, err := c.RegisterPublicKeyTemplate(server, cert.Leaf.PublicKey, hello.ServerName, nil)
		if err != nil {
			return nil, err
		}

		if _, ok := cert.Leaf.PublicKey.(*rsa.PublicKey); ok {
			cert.PrivateKey = &RSAPrivateKey{PrivateKey: *priv}
		} else {
			cert.PrivateKey = priv
		}

		return
	}, nil
}
