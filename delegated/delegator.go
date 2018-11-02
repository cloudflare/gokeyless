//Package delegated implements delegated credentials.
package delegated

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"time"

	"github.com/cloudflare/gokeyless/protocol"
	"github.com/cloudflare/gokeyless/server"
)

// DelegatorConfig stores the parameters the delegator uses to decide which
// requests to grant delegations for.
type DelegatorConfig struct {
	// Time is invoked in order to determine if the credential's validity time
	// is in the permitted interval.
	Time func() time.Time

	// MinTTL is the smallest validity interval for which the delegator will
	// grant delegations.
	MinTTL time.Duration

	// MaxTTL is the largest validity interval for which the delegator will
	// grant delegations. This must not exceed the maximum TTL permitted by the
	// spec: see https://tools.ietf.org/html/draft-ietf-tls-subcerts for
	// details.
	MaxTTL time.Duration

	// SignatureSchemes is the set of signature schemes for which the delegator
	// will grant delegations.
	SignatureSchemes []uint16

	// ProtocolVersions is the set of TLS versions for which the delegator will
	// grant delegations. This must be TLS 1.3 or a draft thereof or a later
	// version of TLS.
	ProtocolVersions []uint16
}

// GetDefaultDelegatorConfig returns a default configuration that permits all
// parameters supported by this implementation.
func GetDefaultDelegatorConfig() *DelegatorConfig {
	return &DelegatorConfig{
		Time:   time.Now,
		MinTTL: 0,
		MaxTTL: MaxTTL,
		SignatureSchemes: []uint16{
			uint16(tls.ECDSAWithP256AndSHA256),
			uint16(tls.ECDSAWithP384AndSHA384),
			uint16(tls.ECDSAWithP521AndSHA512),
		},
		ProtocolVersions: []uint16{
			VersionTLS13,
			VersionTLS13Draft28,
			VersionTLS13Draft23,
		},
	}
}

// Delegator stores the state needed for handling delegation requests.
type Delegator struct {
	keystore  server.Keystore
	cfg       *DelegatorConfig
	certstore map[protocol.SKI]*tls.Certificate
}

type dummyKeystore struct {
	cert *tls.Certificate
}

// Get retrieves the only key we have in the dummy keystore.
func (store *dummyKeystore) Get(op *protocol.Operation) (crypto.Signer, error) {
	tmp := (store.cert.PrivateKey).(ecdsa.PrivateKey)
	return crypto.Signer(&tmp), nil
}

// FromFile creates a delegator from a file with a certificate and and a key.
func FromFile(cert string, key string, ttl time.Duration) (*Delegator, error) {
	ourcert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	conf := GetDefaultDelegatorConfig()
	conf.MaxTTL = ttl
	return NewDelegator(&ourcert, conf)
}

// NewDelegator returns a Delegator structure for the specified certificate and
// configuration. It returns an error if the certificate can't be used with
// delegated credentials.
func NewDelegator(cert *tls.Certificate, cfg *DelegatorConfig) (*Delegator, error) {
	if err := ensureCertificateHasLeaf(cert); err != nil {
		return nil, err
	}
	if !IsDelegationCertificate(cert.Leaf) {
		return nil, errNoDelegationUsage
	}
	if cfg.MinTTL > cfg.MaxTTL {
		return nil, errors.New("MinTTL exceeds MaxTTL")
	}
	if cfg.MaxTTL > MaxTTL {
		return nil, errors.New("MaxTTL exceeds maixum permissiable TTL")
	}
	if len(cfg.SignatureSchemes) == 0 {
		return nil, errors.New("empty SignatureSchemes")
	}
	if len(cfg.ProtocolVersions) == 0 {
		return nil, errors.New("empty ProtocolVersions")
	}
	keystore := dummyKeystore{cert: cert}
	certstore := make(map[protocol.SKI]*tls.Certificate)
	ski, err := protocol.GetSKICert(cert.Leaf)
	if err != nil {
		return nil, err
	}
	certstore[ski] = cert
	return &Delegator{&keystore, cfg, certstore}, nil
}

// DelegatorQuery is what is sent over the wire to request a delegated credential.
type DelegatorQuery struct {
	SKI  protocol.SKI
	TTL  time.Duration
	Cred []byte
}

// Sign processes a delegation request. If the request satisfies the delegator
// parameters, then the delegated credential is encoded and written as the
// response; otherwise, an error is returned.
//
// This function satisfies the criteria for use as an RPC: see
// https://golang.org/pkg/net/rpc/ for details.
func (del *Delegator) Sign(req DelegatorQuery, resp *[]byte) error {
	cred, err := UnmarshalCredential(req.Cred)
	if err != nil {
		return err
	}

	ok := false
	for _, vers := range del.cfg.ProtocolVersions {
		ok = ok || vers == cred.ExpectedVersion
	}
	if !ok {
		return errors.New("protocol version not supported")
	}

	ok = false
	for _, sigalg := range del.cfg.SignatureSchemes {
		ok = ok || sigalg == cred.ExpectedCertVerifyAlgorithm
	}
	if !ok {
		return errors.New("signature scheme not supported")
	}
	cert, found := del.certstore[req.SKI]
	if !found {
		return errors.New("Did not find SKI")
	}

	now := del.cfg.Time()
	cred.ValidTime = now.Sub(cert.Leaf.NotBefore) + req.TTL
	if req.TTL < del.cfg.MinTTL || req.TTL > del.cfg.MaxTTL {
		return errors.New("validity time not in range")
	}

	dc, err := Delegate(cert, cred)
	if err != nil {
		*resp = nil
		return err
	}

	*resp, err = dc.Marshal()
	if err != nil {
		*resp = nil
		return err
	}

	return nil
}
