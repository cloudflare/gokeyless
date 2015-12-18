package client

import (
	"crypto"
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
	"strconv"
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
	// DefaultRemote is a default remote to dial and register keys to.
	DefaultRemote Remote
	// BlacklistIPs is a list of server IPs that this client won't dial.
	BlacklistIPs []net.IP
	// BlacklistPort is the server port to blacklist.
	BlacklistPort int
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
		Dialer:  &net.Dialer{},
		servers: make(map[string]Remote),
		remotes: make(map[gokeyless.SKI]Remote),
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

// Dial smartly establishes a connection to a registered keyless server
// or reuses an existing connection if possible.
func (c *Client) Dial(ski gokeyless.SKI) (*gokeyless.Conn, error) {
	c.m.RLock()
	r, ok := c.remotes[ski]
	c.m.RUnlock()
	if !ok {
		if c.DefaultRemote != nil {
			return nil, fmt.Errorf("no servers registered for SKI %02x", ski)
		}

		r = c.DefaultRemote
	}
	return r.Dial(c)
}

// ActivateServer dials a server and sends an activation request.
func (c *Client) ActivateServer(server string, token []byte) error {
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		return err
	}

	p, err := strconv.Atoi(port)
	if err != nil {
		return err
	}

	r, err := c.LookupServer(host, "", p)
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

// PopulateBlacklist populates the client blacklist using an x509 certificate.
func (c *Client) PopulateBlacklist(cert *x509.Certificate, port int) {
	c.BlacklistPort = port
	c.BlacklistIPs = append(c.BlacklistIPs, cert.IPAddresses...)
	for _, host := range cert.DNSNames {
		if ips, err := net.LookupIP(host); err == nil {
			c.BlacklistIPs = append(c.BlacklistIPs, ips...)
		}
	}
}

// ClearBlacklist empties the client blacklist
func (c *Client) ClearBlacklist() {
	c.BlacklistPort = 0
	c.BlacklistIPs = c.BlacklistIPs[:0]
}

// ValidIP determines if the given IP isn't a blacklisted server IP
func (c *Client) ValidIP(ip net.IP) error {
	for _, badIP := range c.BlacklistIPs {
		if ip.Equal(badIP) {
			return fmt.Errorf("%s is blacklisted", ip)
		}
	}

	return nil
}

// ValidServer determines if the given server can be resolved and doesn't resolve
// to a blacklisted server IP.
func (c *Client) ValidServer(server string) (err error) {
	var host, port string
	if host, port, err = net.SplitHostPort(server); err != nil {
		return
	}

	var p int
	if p, err = strconv.Atoi(port); err != nil {
		return
	}

	if p != c.BlacklistPort {
		return nil
	}

	var ips []net.IP
	if ips, err = net.LookupIP(host); err != nil {
		return
	}

	for _, ip := range ips {
		if err = c.ValidIP(ip); err != nil {
			return
		}
	}

	return nil
}

// AddRemote adds a remote for the given SKI, optionally registering it
// under the given server name.
func (c *Client) AddRemote(server string, r Remote, ski gokeyless.SKI) *PrivateKey {
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

	return &PrivateKey{client: c, ski: ski}
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
		if err = c.ValidServer(server); err != nil {
			log.Errorf("Server %s invalid: %v", server, err)
			return
		}

		var ok bool
		c.m.RLock()
		r, ok = c.servers[server]
		c.m.RUnlock()
		if !ok {
			var host, port string
			if host, port, err = net.SplitHostPort(server); err != nil {
				return
			}
			var p int
			if p, err = strconv.Atoi(port); err != nil {
				return
			}
			if r, err = c.LookupServer(host, "", p); err != nil {
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
