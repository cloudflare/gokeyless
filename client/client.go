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
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless"
	"github.com/lziest/ttlcache"
)

const (
	remoteCacheSize = 512
	remoteCacheTTL  = time.Minute * 5
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
	// TODO: DefaultRemote needs to deal with default server DNS changes automatically.
	// NOTE: For now DefaultRemote is very static to save dns lookup overhead
	DefaultRemote Remote
	// Blacklist is a list of addresses that this client won't dial.
	Blacklist AddrSet
	// m is a Read/Write lock to protect against conccurrent accesses to maps.
	m sync.RWMutex
	// remoteCache maps all known server names to corresponding remote.
	remoteCache *ttlcache.LRU
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
		Dialer:      &net.Dialer{},
		Blacklist:   make(AddrSet),
		remoteCache: ttlcache.NewLRU(remoteCacheSize, remoteCacheTTL, nil),
		remotes:     make(map[gokeyless.SKI]Remote),
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
	log.Infof("add to blacklist addr set: %s", addr)
	as[addr.String()] = true
}

// Contains determines if an addr belongs to the set of addresses.
func (as AddrSet) Contains(addr net.Addr) bool {
	contains, ok := as[addr.String()]
	return ok && contains
}

// PopulateBlacklistFromHostname populates the client blacklist using an hostname.
// All ips resolved from that hostname, appended with port are blacklisted.
func (c *Client) PopulateBlacklistFromHostname(host string, port int) {
	if ips, err := LookupIPs(c.Resolvers, host); err == nil {
		for _, ip := range ips {
			c.Blacklist.Add(&net.TCPAddr{
				IP:   ip,
				Port: port,
			})
		}
	}
}

// PopulateBlacklistFromCert populates the client blacklist using an x509 certificate.
// IPs resolved from domain SANs and IP SANs are put together with port and blacklisted.
func (c *Client) PopulateBlacklistFromCert(cert *x509.Certificate, port int) {
	for _, ip := range cert.IPAddresses {
		c.Blacklist.Add(&net.TCPAddr{
			IP:   ip,
			Port: port,
		})
	}
	for _, host := range cert.DNSNames {
		c.PopulateBlacklistFromHostname(host, port)
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
	if ok {
		return r.Dial(c)
	}
	return c.DialDefault()
}

// DialDefault establishes a connection to the default keyless server.
func (c *Client) DialDefault() (*Conn, error) {
	if c.DefaultRemote == nil {
		return nil, fmt.Errorf("default remote is nil")
	}
	return c.DefaultRemote.Dial(c)
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

// registerSKI associates the SKI of a public key with a particular keyserver.
func (c *Client) registerSKI(server string, ski gokeyless.SKI) error {
	c.m.Lock()
	defer c.m.Unlock()
	// empty server means always associate ski with DefaultRemote
	if server == "" {
		log.Debugf("registering key @default_remote with SKI: %02x", ski)
		c.remotes[ski] = c.DefaultRemote
		return nil
	}

	log.Debugf("registering key @%s with SKI: %02x", server, ski)
	cachedRemote := false
	v, stale := c.remoteCache.Get(server)
	if !stale {
		if r, ok := v.(Remote); ok {
			c.remotes[ski] = r
			cachedRemote = true
		} else {
			log.Error("failed to convert cached remote")
		}
	}

	if !cachedRemote {
		r, err := c.LookupServer(server)
		if err != nil {
			log.Error(err)
			return err
		}
		c.remoteCache.Set(server, r, 0) // use default timeout
		c.remotes[ski] = r
	}
	return nil
}

// RegisterPublicKeyTemplate registers a public key with additional operation template information.
func (c *Client) RegisterPublicKeyTemplate(server string, pub crypto.PublicKey, sni string, serverIP net.IP) (crypto.Signer, error) {
	ski, err := gokeyless.GetSKI(pub)
	if err != nil {
		return nil, err
	}

	if err := c.registerSKI(server, ski); err != nil {
		return nil, err
	}

	// digest is being deprecated, so it's ok to ignore error here
	digest, _ := gokeyless.GetDigest(pub)

	priv := PrivateKey{
		public:   pub,
		client:   c,
		ski:      ski,
		digest:   digest,
		sni:      sni,
		serverIP: serverIP,
	}

	// This is due to an issue in crypto/tls, where an ECDSA key is not allowed to
	// implement Decrypt.
	if _, ok := pub.(*rsa.PublicKey); ok {
		return &Decrypter{priv}, nil
	}
	return &priv, nil
}

// RegisterPublicKey SKIs and registers a public key as being held by a server.
func (c *Client) RegisterPublicKey(server string, pub crypto.PublicKey) (crypto.Signer, error) {
	return c.RegisterPublicKeyTemplate(server, pub, "", nil)
}

// RegisterCert SKIs the public key contained in a certificate and associates it with a particular keyserver.
func (c *Client) RegisterCert(server string, cert *x509.Certificate) (crypto.Signer, error) {
	return c.RegisterPublicKeyTemplate(server, cert.PublicKey, "", nil)
}

// RegisterCertPEM registers a single PEM cert (possibly the leaf of a chain of certs).
func (c *Client) RegisterCertPEM(server string, certsPEM []byte) (crypto.Signer, error) {
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
func (c *Client) RegisterDir(server, dir string, LoadPubKey func([]byte) (crypto.PublicKey, error)) (privkeys []crypto.Signer, err error) {
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

			var priv crypto.Signer
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
