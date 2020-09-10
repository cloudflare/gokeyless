package client

import (
	"context"
	"crypto"
	"crypto/ecdsa"
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
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/protocol"
	"github.com/cloudflare/gokeyless/tracing"
	"github.com/lziest/ttlcache"
	"github.com/opentracing/opentracing-go"
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
	Blacklist *AddrSet
	// remoteCache maps all known server names to corresponding remote.
	remoteCache *ttlcache.LRU
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
		Blacklist:   &AddrSet{},
		remoteCache: ttlcache.NewLRU(remoteCacheSize, remoteCacheTTL, nil),
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
type AddrSet struct {
	addrs []*net.TCPAddr

	subnets []*net.IPNet
	snPorts []int
}

// Add adds an addr to the set of addresses.
func (as *AddrSet) Add(addr net.Addr, port int) {
	switch t := addr.(type) {
	case *net.TCPAddr:
		as.addrs = append(as.addrs, &net.TCPAddr{IP: t.IP, Port: port})
	case *net.IPAddr:
		as.addrs = append(as.addrs, &net.TCPAddr{IP: t.IP, Port: port})
	case *net.IPNet:
		as.subnets = append(as.subnets, t)
		as.snPorts = append(as.snPorts, port)

	default:
		log.Debugf("silently ignoring unexpected address type: %T", addr)
		return
	}

	log.Debugf("add to blacklist addr set: %s", addr)
}

// Contains determines if an addr belongs to the set of addresses.
func (as *AddrSet) Contains(addr net.Addr) bool {
	t, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}

	for _, cand := range as.addrs {
		if t.Port == cand.Port && t.IP.Equal(cand.IP) {
			return true
		}
	}

	for i, sn := range as.subnets {
		if t.Port == as.snPorts[i] && sn.Contains(t.IP) {
			return true
		}
	}

	return false
}

// PopulateBlacklistFromHostname populates the client blacklist using an hostname.
// All ips resolved from that hostname, appended with port are blacklisted.
func (c *Client) PopulateBlacklistFromHostname(host string, port int) {
	// Never attempt to resolve empty hostname
	if host == "" {
		return
	}
	if ips, err := LookupIPs(c.Resolvers, host); err == nil {
		for _, ip := range ips {
			c.Blacklist.Add(&net.IPAddr{IP: ip}, port)
		}
	}
}

// PopulateBlacklistFromCert populates the client blacklist using an x509 certificate.
// IPs resolved from domain SANs and IP SANs are put together with port and blacklisted.
func (c *Client) PopulateBlacklistFromCert(cert *x509.Certificate, port int) {
	for _, ip := range cert.IPAddresses {
		c.Blacklist.Add(&net.IPAddr{IP: ip}, port)
	}
	for _, host := range cert.DNSNames {
		c.PopulateBlacklistFromHostname(host, port)
	}
}

// ClearBlacklist empties the client blacklist
func (c *Client) ClearBlacklist() {
	c.Blacklist = &AddrSet{}
}

// registerSKI associates the SKI of a public key with a particular keyserver.
func (c *Client) getRemote(server string) (Remote, error) {
	// empty server means always associate ski with DefaultRemote
	if server == "" {
		if c.DefaultRemote == nil {
			return nil, fmt.Errorf("default remote is nil")
		}
		return c.DefaultRemote, nil
	}

	v, stale := c.remoteCache.Get(server)
	if v != nil && !stale {
		if r, ok := v.(Remote); ok {
			return r, nil
		}
		log.Error("failed to convert cached remote")
	}

	r, err := c.LookupServer(server)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	c.remoteCache.Set(server, r, 0) // use default timeout
	return r, nil
}

// NewRemoteSignerWithCertID returns a remote keyserver based crypto.Signer
// ski, sni, serverIP, and certID are used to identify the key by the remote
// keyserver.
func NewRemoteSignerWithCertID(ctx context.Context, c *Client, keyserver string, ski protocol.SKI,
	pub crypto.PublicKey, sni string, certID string, serverIP net.IP) (crypto.Signer, error) {
	span, _ := opentracing.StartSpanFromContext(ctx, "client.NewRemoteSignerWithCertID")
	defer span.Finish()
	priv := PrivateKey{
		public:    pub,
		client:    c,
		ski:       ski,
		sni:       sni,
		serverIP:  serverIP,
		keyserver: keyserver,
		certID:    certID,
	}
	var err error
	priv.JaegerSpan, err = tracing.SpanContextToBinary(span.Context())
	if err != nil {
		log.Errorf("failed to inject span: %v", err)
	}

	// This is due to an issue in crypto/tls, where an ECDSA key is not allowed to
	// implement Decrypt.
	if _, ok := pub.(*rsa.PublicKey); ok {
		return &Decrypter{priv}, nil
	}
	return &priv, nil
}

// NewRemoteSigner returns a remote keyserver based crypto.Signer,
// ski, sni, and serverIP are used to identified the key by the remote
// keyserver.
func NewRemoteSigner(ctx context.Context, c *Client, keyserver string, ski protocol.SKI,
	pub crypto.PublicKey, sni string, serverIP net.IP) (crypto.Signer, error) {

	span, _ := opentracing.StartSpanFromContext(ctx, "client.NewRemoteSignerWithCertID")
	defer span.Finish()
	priv := PrivateKey{
		public:    pub,
		client:    c,
		ski:       ski,
		sni:       sni,
		serverIP:  serverIP,
		keyserver: keyserver,
	}
	var err error
	priv.JaegerSpan, err = tracing.SpanContextToBinary(span.Context())
	if err != nil {
		log.Errorf("failed to inject span: %v", err)
	}

	// This is due to an issue in crypto/tls, where an ECDSA key is not allowed to
	// implement Decrypt.
	if _, ok := pub.(*rsa.PublicKey); ok {
		return &Decrypter{priv}, nil
	}
	return &priv, nil
}

// NewRemoteSignerTemplate returns a remote keyserver
// based crypto.Signer with the public key.
// SKI is computed from the public key and along with sni and serverIP,
// the remote Signer uses those key identification info to contact the
// remote keyserver for keyless operations.
func (c *Client) NewRemoteSignerTemplate(ctx context.Context, keyserver string, pub crypto.PublicKey, sni string, serverIP net.IP) (crypto.Signer, error) {
	ski, err := protocol.GetSKI(pub)
	if err != nil {
		return nil, err
	}
	return NewRemoteSigner(ctx, c, keyserver, ski, pub, sni, serverIP)
}

// NewRemoteSignerTemplateWithCertID returns a remote keyserver
// based crypto.Signer with the public key.
// SKI is computed from public key, and along with sni, serverIP, and
// certID the remote signer uses these to contact the remote keyserver.
func (c *Client) NewRemoteSignerTemplateWithCertID(ctx context.Context, keyserver string, pub crypto.PublicKey, sni string, serverIP net.IP, certID string) (crypto.Signer, error) {
	ski, err := protocol.GetSKI(pub)
	if err != nil {
		return nil, err
	}
	return NewRemoteSignerWithCertID(ctx, c, keyserver, ski, pub, sni, certID, serverIP)
}

// NewRemoteSignerByPublicKey returns a remote keyserver based signer
// with the the public key.
func (c *Client) NewRemoteSignerByPublicKey(ctx context.Context, server string, pub crypto.PublicKey) (crypto.Signer, error) {
	return c.NewRemoteSignerTemplate(ctx, server, pub, "", nil)
}

// NewRemoteSignerByCert returns a remote keyserver based signer
// with the the public key contained in a x509.Certificate.
func (c *Client) NewRemoteSignerByCert(ctx context.Context, server string, cert *x509.Certificate) (crypto.Signer, error) {
	return c.NewRemoteSignerTemplate(ctx, server, cert.PublicKey, "", nil)
}

// NewRemoteSignerByCertPEM returns a remote keyserver based signer
// with the public key extracted from  a single PEM cert
// (possibly the leaf of a chain of certs).
func (c *Client) NewRemoteSignerByCertPEM(ctx context.Context, server string, certsPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(certsPEM)
	if block == nil {
		return nil, errors.New("couldn't parse PEM bytes")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return c.NewRemoteSignerTemplate(ctx, server, cert.PublicKey, "", nil)
}

var (
	pubkeyExt = regexp.MustCompile(`.+\.pubkey`)
	crtExt    = regexp.MustCompile(`.+\.crt`)
)

// ScanDir reads all .pubkey and .crt files from a directory and returns associated PublicKey structs.
func (c *Client) ScanDir(server, dir string, LoadPubKey func([]byte) (crypto.PublicKey, error)) (privkeys []crypto.Signer, err error) {
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		isPubKey := pubkeyExt.MatchString(info.Name())
		isCert := crtExt.MatchString(info.Name())
		if !info.IsDir() && (isPubKey || isCert) {
			log.Infof("Loading %s...\n", path)

			in, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			var priv crypto.Signer
			if LoadPubKey == nil {
				LoadPubKey = DefaultLoadPubKey
			}
			if isPubKey {
				pub, err := LoadPubKey(in)
				if err != nil {
					return err
				}

				if priv, err = c.NewRemoteSignerByPublicKey(context.Background(), server, pub); err != nil {
					return err
				}
			} else {
				if priv, err = c.NewRemoteSignerByCertPEM(context.Background(), server, in); err != nil {
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

	cert.PrivateKey, err = c.NewRemoteSignerByCert(context.TODO(), server, cert.Leaf)
	if err != nil {
		return fail(err)
	}

	return cert, nil
}

func DefaultLoadPubKey(in []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(in)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse DER encoded public key: " + err.Error())
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("unknown/unsupported type of public key")
	}
}
