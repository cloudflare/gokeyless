// Copyright 2018 Cloudflare, Inc.

// This package implements the backend for draft-02 of Delegated credentials for
// TLS (https://tools.ietf.org/html/draft-ietf-tls-subcerts), an IETF Internet
// draft and proposed TLS extension. If the client supports this extension, then
// the server may use a "delegated credential" as the signing key in the
// handshake. A delegated credential is a short-lived signing key pair delegated
// to the server by an entity trusted by the client. This allows a middlebox to
// terminate a TLS connection on behalf of the entity; for example, this can be
// used to delegate TLS termination to a reverse proxy. Credentials can't be
// revoked; in order to mitigate risk in case the middlebox is compromised, the
// credential is only valid for a short time (days, hours, or even minutes).
//
// This package provides functionalities for minting and validating delegated
// credentials. It also implements parts of the X.509 standard for EdDSA
// siganture schemes (draft-04), as needed for minting DCss.
package delegated

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const (
	MaxTTLSeconds     = 60 * 60 * 24 * 7 // 7 days
	MaxTTL            = time.Duration(MaxTTLSeconds * time.Second)
	dcMaxPublicKeyLen = 1 << 24 // Bytes
	dcMaxSignatureLen = 1 << 16 // Bytes

	// TLS 1.3 versions not defined in crypto/tls.
	//
	// NOTE: Once TLS 1.3 is available upstream, these code points should be
	// removed.
	VersionTLS13        uint16 = 0x0304
	VersionTLS13Draft23 uint16 = 0x7f00 | 23
	VersionTLS13Draft28 uint16 = 0x7f00 | 28

	// TLS signature schemes not defined in crypto/tls.
	//
	// NOTE: Once these are available upstream, these code points should be
	// removed.
	Ed25519 tls.SignatureScheme = 0x0807
)

var errNoDelegationUsage = errors.New("certificate not authorized for delegation")

// delegationUsageId is the DelegationUsage X.509 extension OID.
var DelegationUsageId = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 44}

// CreateDelegationUsagePKIXExtension returns a pkix.Extension that every delegation
// certificate must have.
//
// NOTE: Brendan McMillion suggests adding the DelegationUsage extension as a
// flag `PermitsDelegationUsage` for the `x509.Certificate` structure. But we
// can't make this change until go-crypto includes crypto/x509. Once we upstream
// this code, we'll want to do modify x509.Certficate and do away with this
// function.
func CreateDelegationUsagePKIXExtension() *pkix.Extension {
	return &pkix.Extension{
		Id:       DelegationUsageId,
		Critical: false,
		Value:    nil,
	}
}

// IsDelegationCertificate returns true if a certificate can be used for
// delegated credentials.
func IsDelegationCertificate(cert *x509.Certificate) bool {
	// Check that the digitalSignature key usage is set.
	if (cert.KeyUsage & x509.KeyUsageDigitalSignature) == 0 {
		return false
	}

	// Check that the certificate has the DelegationUsage extension and that
	// it's non-critical (per the spec).
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(DelegationUsageId) {
			return true
		}
	}
	return false
}

// Credential structure stores the public components of a credential.
type Credential struct {
	// The serialized form of the credential.
	Raw []byte

	// The amount of time for which the credential is valid. Specifically,
	// the credential expires ValidTime seconds after the notBefore of the
	// delegation certificate. The delegator shall not issue delegated
	// credentials that are valid for more than 7 days from the current time.
	//
	// When this data structure is serialized, this value is converted to a
	// uint32 representing the duration in seconds.
	ValidTime time.Duration

	// The signature scheme associated with the credential public key.
	ExpectedCertVerifyAlgorithm uint16

	// The version of TLS in which the credential will be used.
	ExpectedVersion uint16

	// The credential public key.
	PublicKey crypto.PublicKey
}

// NewCredential generates a key pair for the provided signature algorithm,
// protocol version, and validity time.
func NewCredential(scheme, version uint16, validTime time.Duration) (*Credential, crypto.PrivateKey, error) {
	// The granularity of DC validity in seconds.
	validTime = validTime.Round(time.Second)

	// Generate a new key pair.
	var err error
	var sk crypto.PrivateKey
	var pk crypto.PublicKey
	switch tls.SignatureScheme(scheme) {
	case tls.ECDSAWithP256AndSHA256,
		tls.ECDSAWithP384AndSHA384,
		tls.ECDSAWithP521AndSHA512:
		sk, err = ecdsa.GenerateKey(GetCurve(scheme), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pk = sk.(*ecdsa.PrivateKey).Public()

	default:
		return nil, nil, fmt.Errorf("unsupported signature scheme: 0x%04x", scheme)
	}

	return &Credential{
		ValidTime:                   validTime,
		ExpectedCertVerifyAlgorithm: scheme,
		ExpectedVersion:             version,
		PublicKey:                   pk,
	}, sk, nil
}

// IsExpired returns true if the credential has expired. The end of the validity
// interval is defined as the delegation certificate's notBefore field (start)
// plus the validity time. This function simply checks that the current time
// (now) is before the end of the valdity interval.
func (cred *Credential) IsExpired(start, now time.Time) bool {
	end := start.Add(cred.ValidTime)
	return !now.Before(end)
}

// InvalidTTL returns true if the credential's validity period is longer than
// the maximum permitted. This is defined by the certificate's notBefore field
// (start) plus the ValidTime, minus the current time (now).
func (cred *Credential) InvalidTTL(start, now time.Time) bool {
	return cred.ValidTime > (now.Sub(start) + MaxTTL).Round(time.Second)
}

// marshalPublicKey returns a DER encoded SubjectPublicKeyInfo structure (as
// defined in the X.509 standard) that encodes the credential public key.
func (cred *Credential) marshalPublicKey() ([]byte, error) {
	switch tls.SignatureScheme(cred.ExpectedCertVerifyAlgorithm) {
	case tls.ECDSAWithP256AndSHA256,
		tls.ECDSAWithP384AndSHA384,
		tls.ECDSAWithP521AndSHA512:
		return x509.MarshalPKIXPublicKey(cred.PublicKey)

	default:
		return nil, fmt.Errorf("unsupported signature scheme: 0x%04x", cred.ExpectedCertVerifyAlgorithm)
	}
}

// Marshal encodes a credential as per the spec.
func (cred *Credential) Marshal() ([]byte, error) {
	paramsLen := 8

	// Write the valid_time, scheme, and version fields.
	serialized := make([]byte, paramsLen+3) // +3 for the length of the public key field.
	binary.BigEndian.PutUint32(serialized, uint32(cred.ValidTime/time.Second))
	binary.BigEndian.PutUint16(serialized[4:], cred.ExpectedCertVerifyAlgorithm)
	binary.BigEndian.PutUint16(serialized[6:], cred.ExpectedVersion)

	// Encode the public key and assert that the encoding is no longer than 2^16
	// bytes (per the spect).
	serializedPublicKey, err := cred.marshalPublicKey()
	if err != nil {
		return nil, err
	}
	if len(serializedPublicKey) > dcMaxPublicKeyLen {
		return nil, errors.New("public key is too long")
	}

	// Write the length of the public key field, which may be 2^24 bytes long.
	putUint24(serialized[paramsLen:], len(serializedPublicKey))

	// Write the public key field.
	serialized = append(serialized, serializedPublicKey...)
	cred.Raw = serialized
	return serialized, nil
}

// UnmarshalCredential decodes a credential and returns it.
func UnmarshalCredential(serialized []byte) (*Credential, error) {
	paramsLen := 8

	// Bytes 0:4 are the valid_time field, 4:6 are the scheme field, 6:8 are the
	// version field, and 8:10 are the length of the serialized
	// SubjectPublicKeyInfo.
	if len(serialized) < paramsLen+3 {
		return nil, errors.New("credential is too short")
	}

	// Parse the valid_time, scheme, and version fields.
	validTime := time.Duration(binary.BigEndian.Uint32(serialized)) * time.Second
	scheme := binary.BigEndian.Uint16(serialized[4:])
	version := binary.BigEndian.Uint16(serialized[6:])

	// Parse the public key.
	pk, err := unmarshalPublicKey(serialized[paramsLen+3:])
	if err != nil {
		return nil, err
	}

	return &Credential{
		Raw:                         serialized,
		ValidTime:                   validTime,
		ExpectedCertVerifyAlgorithm: scheme,
		ExpectedVersion:             version,
		PublicKey:                   pk,
	}, nil
}

// unmarshalPublicKey parses a DER-encoded SubjectPublicKeyInfo
// structure into a public key.
func unmarshalPublicKey(serialized []byte) (crypto.PublicKey, error) {
	publicKey, err := x509.ParsePKIXPublicKey(serialized)
	if err != nil {
		return nil, err
	}

	switch pk := publicKey.(type) {
	case *ecdsa.PublicKey:
		return pk, nil
	default:
		return nil, fmt.Errorf("unsupported delegation key type: %T", pk)
	}
}

// getCredentialLen returns the number of bytes comprising the serialized
// credential that starts at the beginning of the input slice. It returns an
// error if the input is too short to contain a credential.
func getCredentialLen(serialized []byte) (int, error) {
	paramsLen := 8
	if len(serialized) < paramsLen+2 {
		return 0, errors.New("credential is too short")
	}
	// First several bytes are the valid_time, scheme, and version fields.
	serialized = serialized[paramsLen:]

	// The next 3 bytes are the length of the serialized public key.
	serializedPublicKeyLen := getUint24(serialized)
	serialized = serialized[3:]

	if len(serialized) < serializedPublicKeyLen {
		return 0, errors.New("public key of credential is too short")
	}

	return paramsLen + 3 + serializedPublicKeyLen, nil
}

// DelegatedCredential stores a credential and its delegation.
type DelegatedCredential struct {
	// The serialized form of the delegated credential.
	Raw []byte

	// The credential, which contains a public and its validity time.
	Cred *Credential

	// The signature scheme used to sign the credential.
	Algorithm uint16

	// The credential's delegation.
	Signature []byte
}

// ensureCertificateHasLeaf parses the leaf certificate if needed.
func ensureCertificateHasLeaf(cert *tls.Certificate) error {
	var err error
	if cert.Leaf == nil {
		if len(cert.Certificate[0]) == 0 {
			return errors.New("missing leaf certificate")
		}
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return err
		}
	}
	return nil
}

// Delegate signs a credential using the provided certificate and returns the
// delegated credential.
func Delegate(cert *tls.Certificate, cred *Credential) (*DelegatedCredential, error) {
	var err error
	if err = ensureCertificateHasLeaf(cert); err != nil {
		return nil, err
	}

	//Check that the leaf certificate can be used for delegation.
	if !IsDelegationCertificate(cert.Leaf) {
		return nil, errNoDelegationUsage
	}

	// Extract the delegator signature scheme from the certificate.
	var delegatorAlgorithm tls.SignatureScheme
	switch sk := cert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		// Ensure the certificate public key type matches the public key.
		if cert.Leaf.PublicKeyAlgorithm != x509.ECDSA {
			return nil, fmt.Errorf("certificate public key type does not match public key")
		}

		// Set the signature algorithm of the delegation certificate.
		pk := sk.Public().(*ecdsa.PublicKey)
		curveName := pk.Curve.Params().Name
		if curveName == "P-256" {
			delegatorAlgorithm = tls.ECDSAWithP256AndSHA256
		} else if curveName == "P-384" {
			delegatorAlgorithm = tls.ECDSAWithP384AndSHA384
		} else if curveName == "P-521" {
			delegatorAlgorithm = tls.ECDSAWithP521AndSHA512
		} else {
			return nil, fmt.Errorf("unrecognized curve %s", curveName)
		}
	default:
		delegatorAlgorithm = tls.ECDSAWithP256AndSHA256
		//		return nil, fmt.Errorf("unsupported delgation key type: %T", sk)
	}

	// Prepare the credential for digital signing.
	rawCred, err := cred.Marshal()
	if err != nil {
		return nil, err
	}
	hash := GetHash(uint16(delegatorAlgorithm))
	in := prepareDelegation(hash, rawCred, cert.Leaf.Raw, uint16(delegatorAlgorithm))

	// Sign the credential.
	var sig []byte
	opts := crypto.SignerOpts(hash)
	switch sk := cert.PrivateKey.(type) {
	case crypto.Signer:
		sig, err = sk.Sign(rand.Reader, in, opts)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("Wrong type %v", cert.PrivateKey)
	}

	return &DelegatedCredential{
		Cred:      cred,
		Algorithm: uint16(delegatorAlgorithm),
		Signature: sig,
	}, nil
}

// NewDelegatedCredential creates a new delegated credential using the provided
// certificate for delegation. It generates a public/private key pair for the
// provided signature algorithm (scheme), validity interval (defined by
// cert.Leaf.notBefore and validTime), and TLS version (version), and signs
// it using the provided certificate.
func NewDelegatedCredential(cert *tls.Certificate, scheme, version uint16, validTime time.Duration) (*DelegatedCredential, crypto.PrivateKey, error) {
	cred, sk, err := NewCredential(scheme, version, validTime)
	if err != nil {
		return nil, nil, err
	}

	dc, err := Delegate(cert, cred)
	if err != nil {
		return nil, nil, err
	}
	return dc, sk, nil
}

// Validate checks that that the signature is valid, that the credential hasn't
// expired, and that the TTL is valid. It also checks that certificate can be
// used for delegation.
func (dc *DelegatedCredential) Validate(cert *x509.Certificate, now time.Time) (bool, error) {
	// Check that the cert can delegate.
	if !IsDelegationCertificate(cert) {
		return false, errNoDelegationUsage
	}

	if dc.Cred.IsExpired(cert.NotBefore, now) {
		return false, errors.New("credential has expired")
	}

	if dc.Cred.InvalidTTL(cert.NotBefore, now) {
		return false, errors.New("credential TTL is invalid")
	}

	// Prepare the credential for verification.
	rawCred, err := dc.Cred.Marshal()
	if err != nil {
		return false, err
	}
	hash := GetHash(dc.Algorithm)
	in := prepareDelegation(hash, rawCred, cert.Raw, dc.Algorithm)

	switch tls.SignatureScheme(dc.Algorithm) {
	case tls.ECDSAWithP256AndSHA256,
		tls.ECDSAWithP384AndSHA384,
		tls.ECDSAWithP521AndSHA512:
		pk, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return false, errors.New("expected ECDSA public key")
		}
		sig := new(ecdsaSignature)
		if _, err := asn1.Unmarshal(dc.Signature, sig); err != nil {
			return false, err
		}
		return ecdsa.Verify(pk, in, sig.R, sig.S), nil

	default:
		return false, fmt.Errorf(
			"unsupported signature scheme: 0x%04x", dc.Algorithm)
	}
}

// Marshal encodes a DelegatedCredential structure per the spec. It also sets
// dc.Raw to the output as a side effect.
func (dc *DelegatedCredential) Marshal() ([]byte, error) {
	// The credential.
	serialized, err := dc.Cred.Marshal()
	if err != nil {
		return nil, err
	}

	// The scheme.
	serializedAlgorithm := make([]byte, 2)
	binary.BigEndian.PutUint16(serializedAlgorithm, uint16(dc.Algorithm))
	serialized = append(serialized, serializedAlgorithm...)

	// The signature.
	if len(dc.Signature) > dcMaxSignatureLen {
		return nil, errors.New("signature is too long")
	}
	serializedSignature := make([]byte, 2)
	binary.BigEndian.PutUint16(serializedSignature, uint16(len(dc.Signature)))
	serializedSignature = append(serializedSignature, dc.Signature...)
	serialized = append(serialized, serializedSignature...)

	dc.Raw = serialized
	return serialized, nil
}

// UnmarshalDelegatedCredential decodes a DelegatedCredential structure.
func UnmarshalDelegatedCredential(serialized []byte) (*DelegatedCredential, error) {
	// Get the length of the serialized credential that begins at the start of
	// the input slice.
	serializedCredentialLen, err := getCredentialLen(serialized)
	if err != nil {
		return nil, err
	}

	// Parse the credential.
	cred, err := UnmarshalCredential(serialized[:serializedCredentialLen])
	if err != nil {
		return nil, err
	}

	// Parse the signature scheme.
	serialized = serialized[serializedCredentialLen:]
	if len(serialized) < 4 {
		return nil, errors.New("delegated credential is too short")
	}
	scheme := binary.BigEndian.Uint16(serialized)

	// Parse the signature length.
	serialized = serialized[2:]
	serializedSignatureLen := binary.BigEndian.Uint16(serialized)

	// Prase the signature.
	serialized = serialized[2:]
	if len(serialized) < int(serializedSignatureLen) {
		return nil, errors.New("signature of delegated credential is too short")
	}
	sig := serialized[:serializedSignatureLen]

	return &DelegatedCredential{
		Raw:       serialized,
		Cred:      cred,
		Algorithm: scheme,
		Signature: sig,
	}, nil
}

// GetCurve maps the SignatureScheme to its corresponding elliptic.Curve.
func GetCurve(scheme uint16) elliptic.Curve {
	switch tls.SignatureScheme(scheme) {
	case tls.ECDSAWithP256AndSHA256:
		return elliptic.P256()
	case tls.ECDSAWithP384AndSHA384:
		return elliptic.P384()
	case tls.ECDSAWithP521AndSHA512:
		return elliptic.P521()
	default:
		return nil
	}
}

// GetHash maps the SignatureScheme to its corresponding hash function.
func GetHash(scheme uint16) crypto.Hash {
	switch tls.SignatureScheme(scheme) {
	case tls.ECDSAWithP256AndSHA256:
		return crypto.SHA256
	case tls.ECDSAWithP384AndSHA384:
		return crypto.SHA384
	case tls.ECDSAWithP521AndSHA512:
		return crypto.SHA512
	default:
		return 0 // Unknown hash function
	}
}

// prepareDelegation returns a hash of the message that the delegator is to
// sign. The inputs are the credential (cred), the DER-encoded delegator
// certificate (delegatorCert) and the signature scheme of the delegator
// (delegatorScheme).
func prepareDelegation(hash crypto.Hash, cred, delegatorCert []byte, delegatorAlgorithm uint16) []byte {
	h := hash.New()

	// The header.
	h.Write(bytes.Repeat([]byte{0x20}, 64))
	h.Write([]byte("TLS, server delegated credentials"))
	h.Write([]byte{0x00})

	// The delegation certificate.
	h.Write(delegatorCert)

	// The credential.
	h.Write(cred)

	// The delegator signature scheme.
	var serializedAlgorithm [2]byte
	binary.BigEndian.PutUint16(serializedAlgorithm[:], uint16(delegatorAlgorithm))
	h.Write(serializedAlgorithm[:])

	return h.Sum(nil)
}

type ecdsaSignature struct {
	R, S *big.Int
}

func getUint24(b []byte) int {
	n := int(b[2])
	n += int(b[1]) << 8
	n += int(b[0]) << 16
	return n
}

func putUint24(b []byte, n int) {
	b[0] = byte(n >> 16)
	b[1] = byte(n >> 8)
	b[2] = byte(n & 0xff)
}
