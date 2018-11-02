package delegated

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"
)

// This test key was generated using cmd/dcutil/dcutil.go.
var delegatorCertPEM = `-----BEGIN CERTIFICATE-----
MIIBdzCCAR2gAwIBAgIQLVIvEpo0/0TzRja4ImvB1TAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE4MDcwMzE2NTE1M1oXDTE5MDcwMzE2NTE1M1ow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOhB
U6adaAgliLaFc1PAo9HBO4Wish1G4df3IK5EXLy+ooYfmkfzT1FxqbNLZufNYzve
25fmpal/1VJAjpVyKq2jVTBTMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMA8GA1UdEQQIMAaHBH8AAAEwDQYJKwYBBAGC
2kssBAAwCgYIKoZIzj0EAwIDSAAwRQIhAPNwRk6cygm6zO5rjOzohKYWS+1KuWCM
OetDIvU4mdyoAiAGN97y3GJccYn9ZOJS4UOqhr9oO8PuZMLgdq4OrMRiiA==
-----END CERTIFICATE-----
`

var delegatorKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJDVlo+sJolMcNjMkfCGDUjMJcE4UgclcXGCrOtbJAi2oAoGCCqGSM49
AwEHoUQDQgAE6EFTpp1oCCWItoVzU8Cj0cE7haKyHUbh1/cgrkRcvL6ihh+aR/NP
UXGps0tm581jO97bl+alqX/VUkCOlXIqrQ==
-----END EC PRIVATE KEY-----
`

// This test key was generated using generate_cert.go in crypto/tls. Example
// usage: "go run generate_cert.go -ecdsa-curve P256 -host 127.0.0.1".
var nonDelegatorCertPEM = `-----BEGIN CERTIFICATE-----
MIIBaTCCAQ6gAwIBAgIQSUo+9uaip3qCW+1EPeHZgDAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE4MDYxMjIzNDAyNloXDTE5MDYxMjIzNDAyNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLf7
fiznPVdc3V5mM3ymswU2/IoJaq/deA6dgdj50ozdYyRiAPjxzcz9zRsZw1apTF/h
yNfiLhV4EE1VrwXcT5OjRjBEMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMA8GA1UdEQQIMAaHBH8AAAEwCgYIKoZIzj0E
AwIDSQAwRgIhANXG0zmrVtQBK0TNZZoEGMOtSwxmiZzXNe+IjdpxO3TiAiEA5VYx
0CWJq5zqpVXbJMeKVMASo2nrXZoA6NhJvFQ97hw=
-----END CERTIFICATE-----
`

var nonDelegatorKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMw9DiOfGI1E/XZrrW2huZSjYi0EKwvVjAe+dYtyFsSloAoGCCqGSM49
AwEHoUQDQgAEt/t+LOc9V1zdXmYzfKazBTb8iglqr914Dp2B2PnSjN1jJGIA+PHN
zP3NGxnDVqlMX+HI1+IuFXgQTVWvBdxPkw==
-----END EC PRIVATE KEY-----
`

var testDelegCredPEM = `-----BEGIN DELEGATED CREDENTIAL-----
AAlKdwQDAwMAAFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASOonqCo5WpBO6x
/Dmh9MxAq/eL18f/b8up8LyBn9fGabVfTeIU3wSA4i+NvVJJ1dnxXhUZkqWj28J2
Nme6AdXhBAMASDBGAiEAhfhxsOYss5VNDe+AqDhfk9N/MR5vS/n2GLaTP8GIHdYC
IQCRb/TzCC2eptI4RNfm+h78RmXOwRkQVA2lLH+4fIY1og==
-----END DELEGATED CREDENTIAL-----
`

var testCert tls.Certificate
var testDelegationCert tls.Certificate
var testNow time.Time

func init() {
	var err error

	// Use a fixed time for testing at which time the test certificates and DCs
	// are valid.
	testNow = time.Date(2018, 07, 03, 18, 0, 0, 234234, time.UTC)

	// The delegation certificate.
	testDelegationCert, err = tls.X509KeyPair([]byte(delegatorCertPEM), []byte(delegatorKeyPEM))
	if err != nil {
		panic(err)
	}
	testDelegationCert.Leaf, err = x509.ParseCertificate(testDelegationCert.Certificate[0])
	if err != nil {
		panic(err)
	}

	// The standard certificate.
	testCert, err = tls.X509KeyPair([]byte(nonDelegatorCertPEM), []byte(nonDelegatorKeyPEM))
	if err != nil {
		panic(err)
	}
	testCert.Leaf, err = x509.ParseCertificate(testCert.Certificate[0])
	if err != nil {
		panic(err)
	}
}

func checkECDSAPublicKeysEqual(
	publicKey, publicKey2 crypto.PublicKey, scheme uint16) error {

	curve := GetCurve(scheme)
	pk := publicKey.(*ecdsa.PublicKey)
	pk2 := publicKey2.(*ecdsa.PublicKey)
	serializedPublicKey := elliptic.Marshal(curve, pk.X, pk.Y)
	serializedPublicKey2 := elliptic.Marshal(curve, pk2.X, pk2.Y)
	if !bytes.Equal(serializedPublicKey2, serializedPublicKey) {
		return errors.New("PublicKey mismatch")
	}
	return nil
}

func checkCredentialsEqual(cred, cred2 *Credential) error {
	if cred2.ValidTime != cred.ValidTime {
		return fmt.Errorf("ValidTime mismatch: got %d; want %d", cred2.ValidTime, cred.ValidTime)
	}
	if cred2.ExpectedCertVerifyAlgorithm != cred.ExpectedCertVerifyAlgorithm {
		return fmt.Errorf("scheme mismatch: got %04x; want %04x", cred2.ExpectedCertVerifyAlgorithm, cred.ExpectedCertVerifyAlgorithm)
	}
	if cred2.ExpectedVersion != cred.ExpectedVersion {
		return fmt.Errorf("version mismatch: got %04x; want %04x", cred2.ExpectedVersion, cred.ExpectedVersion)
	}

	switch tls.SignatureScheme(cred.ExpectedCertVerifyAlgorithm) {
	case tls.ECDSAWithP256AndSHA256,
		tls.ECDSAWithP384AndSHA384,
		tls.ECDSAWithP521AndSHA512:
		return checkECDSAPublicKeysEqual(cred.PublicKey, cred2.PublicKey, cred.ExpectedCertVerifyAlgorithm)

	default:
		return fmt.Errorf("Unknown scheme: %04x", cred.ExpectedCertVerifyAlgorithm)
	}
}

// Test delegation and validation of credentials.
func TestDelegateValidate(t *testing.T) {
	scheme := uint16(tls.ECDSAWithP256AndSHA256)
	ver := uint16(tls.VersionTLS12)
	cert := &testDelegationCert

	validTime := testNow.Sub(cert.Leaf.NotBefore) + MaxTTL
	shortValidTime := testNow.Sub(cert.Leaf.NotBefore) + time.Second

	dc, _, err := NewDelegatedCredential(cert, scheme, ver, validTime)
	if err != nil {
		t.Fatal(err)
	}

	// Test validation of good DC.
	if v, err := dc.Validate(cert.Leaf, testNow); err != nil {
		t.Error(err)
	} else if !v {
		t.Error("good DC is invalid; want valid")
	}

	// Test validation of expired DC.
	tooLate := testNow.Add(MaxTTL).Add(time.Nanosecond)
	if v, err := dc.Validate(cert.Leaf, tooLate); err == nil {
		t.Error("expired DC validation succeeded; want failure")
	} else if v {
		t.Error("expired DC is valid; want invalid")
	}

	// Test credential scheme binding.
	dc.Cred.ExpectedCertVerifyAlgorithm = uint16(tls.ECDSAWithP384AndSHA384)
	if v, err := dc.Validate(cert.Leaf, testNow); err != nil {
		t.Fatal(err)
	} else if v {
		t.Error("DC with credential scheme is valid; want invalid")
	}
	dc.Cred.ExpectedCertVerifyAlgorithm = scheme

	// Test protocol binding.
	dc.Cred.ExpectedVersion = tls.VersionSSL30
	if v, err := dc.Validate(cert.Leaf, testNow); err != nil {
		t.Fatal(err)
	} else if v {
		t.Error("DC with wrong version is valid; want invalid")
	}
	dc.Cred.ExpectedVersion = ver

	// Test signature algorithm binding.
	dc.Algorithm = uint16(tls.ECDSAWithP521AndSHA512)
	if v, err := dc.Validate(cert.Leaf, testNow); err != nil {
		t.Fatal(err)
	} else if v {
		t.Error("DC with wrong scheme is valid; want invalid")
	}
	dc.Algorithm = uint16(tls.ECDSAWithP256AndSHA256)

	// Test delegation certificate binding.
	cert.Leaf.Raw[0] ^= byte(42)
	if v, err := dc.Validate(cert.Leaf, testNow); err != nil {
		t.Fatal(err)
	} else if v {
		t.Error("DC with wrong cert is valid; want invalid")
	}
	cert.Leaf.Raw[0] ^= byte(42)

	// Test validation of DC who's TTL is too long.
	dc2, _, err := NewDelegatedCredential(cert, uint16(tls.ECDSAWithP256AndSHA256), ver, validTime+time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := dc2.Validate(cert.Leaf, testNow); err == nil {
		t.Error("DC validation with long TTL succeeded; want failure")
	} else if v {
		t.Error("DC with long TTL is valid; want invalid")
	}

	// Test validation of DC who's TTL is short.
	dc3, _, err := NewDelegatedCredential(cert, uint16(tls.ECDSAWithP256AndSHA256), ver, shortValidTime)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := dc3.Validate(cert.Leaf, testNow); err != nil {
		t.Error(err)
	} else if !v {
		t.Error("good DC is invalid; want valid")
	}

	// Test validation of DC using a certificate that can't delegate.
	if v, err := dc.Validate(testCert.Leaf, testNow); err != errNoDelegationUsage {
		t.Error("DC validation with non-delegation cert succeeded; want failure")
	} else if v {
		t.Error("DC with non-delegation cert is valid; want invalid")
	}
}

// Test decoding of a delegated credential.
func TestUnmarshal(t *testing.T) {
	cert := &testDelegationCert

	b, _ := pem.Decode([]byte(testDelegCredPEM))
	dc, err := UnmarshalDelegatedCredential(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if ok, err := dc.Validate(cert.Leaf, testNow); err != nil {
		t.Fatalf("DC validation fails: %s", err)
	} else if !ok {
		t.Fatal("DC validation fails: want success")
	}
}

// Test encoding/decoding of delegated credentials.
func TestDelegatedCredentialMarshalUnmarshal(t *testing.T) {
	cert := &testDelegationCert
	deleg, _, err := NewDelegatedCredential(cert,
		uint16(tls.ECDSAWithP256AndSHA256),
		tls.VersionTLS12,
		testNow.Sub(cert.Leaf.NotBefore)+MaxTTL)
	if err != nil {
		t.Fatal(err)
	}

	serialized, err := deleg.Marshal()
	if err != nil {
		t.Error(err)
	}

	deleg2, err := UnmarshalDelegatedCredential(serialized)
	if err != nil {
		t.Error(err)
	}

	err = checkCredentialsEqual(deleg.Cred, deleg2.Cred)
	if err != nil {
		t.Error(err)
	}

	if deleg.Algorithm != deleg2.Algorithm {
		t.Errorf("scheme mismatch: got %04x; want %04x",
			deleg2.Algorithm, deleg.Algorithm)
	}

	if !bytes.Equal(deleg2.Signature, deleg.Signature) {
		t.Error("Signature mismatch")
	}
}
