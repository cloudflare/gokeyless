// Package params provides parameters useful in testing cryptographic operations.
package params

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rsa"

	"github.com/cloudflare/gokeyless/protocol"
)

// RSASignParams represents a set of parameters to an RSA signing operation.
type RSASignParams struct {
	Opcode      protocol.Op       // The Keyless protocol opcode for this operation
	Bits        int               // The size of the key in bits
	Opts        crypto.SignerOpts // Options to the signing function
	PayloadSize int               // The size of the payload to be signed
}

// NOTE: RSAMD5SHA1Params' PayloadSize is 36 because that's the sum of 16
// (the size of an MD5 hash) and 20 (the size of a SHA1 hash).

var (
	RSAMD5SHA1Params   = RSASignParams{Opcode: protocol.OpRSASignMD5SHA1, Opts: crypto.MD5SHA1, PayloadSize: 36}
	RSASHA1Params      = RSASignParams{Opcode: protocol.OpRSASignSHA1, Opts: crypto.SHA1, PayloadSize: 20}
	RSASHA224Params    = RSASignParams{Opcode: protocol.OpRSASignSHA224, Opts: crypto.SHA224, PayloadSize: 28}
	RSASHA256Params    = RSASignParams{Opcode: protocol.OpRSASignSHA256, Opts: crypto.SHA256, PayloadSize: 32}
	RSASHA384Params    = RSASignParams{Opcode: protocol.OpRSASignSHA384, Opts: crypto.SHA384, PayloadSize: 48}
	RSASHA512Params    = RSASignParams{Opcode: protocol.OpRSASignSHA512, Opts: crypto.SHA512, PayloadSize: 64}
	RSAPSSSHA256Params = RSASignParams{Opcode: protocol.OpRSAPSSSignSHA256, Opts: optsToRSAPSS(crypto.SHA256), PayloadSize: 32}
	RSAPSSSHA384Params = RSASignParams{Opcode: protocol.OpRSAPSSSignSHA384, Opts: optsToRSAPSS(crypto.SHA384), PayloadSize: 48}
	RSAPSSSHA512Params = RSASignParams{Opcode: protocol.OpRSAPSSSignSHA512, Opts: optsToRSAPSS(crypto.SHA512), PayloadSize: 64}
)

func optsToRSAPSS(opts crypto.SignerOpts) crypto.SignerOpts {
	return &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: opts.HashFunc()}
}

// ECDSASignParams represents a set of parameters to an ECDSA signing operation.
type ECDSASignParams struct {
	Opcode      protocol.Op       // The Keyless protocol opcode for this operation
	Curve       elliptic.Curve    // The ECDSA curve to use for signing
	Opts        crypto.SignerOpts // Options to the signing function
	PayloadSize int               // The size of the payload to be signed
}

var (
	ECDSASHA224Params = ECDSASignParams{Opcode: protocol.OpECDSASignSHA224, Curve: elliptic.P256(), Opts: crypto.SHA224, PayloadSize: 28}
	ECDSASHA256Params = ECDSASignParams{Opcode: protocol.OpECDSASignSHA256, Curve: elliptic.P256(), Opts: crypto.SHA256, PayloadSize: 32}
	ECDSASHA384Params = ECDSASignParams{Opcode: protocol.OpECDSASignSHA384, Curve: elliptic.P384(), Opts: crypto.SHA384, PayloadSize: 48}
	ECDSASHA512Params = ECDSASignParams{Opcode: protocol.OpECDSASignSHA512, Curve: elliptic.P521(), Opts: crypto.SHA512, PayloadSize: 64}
)

const (
	// RSAURI and ECDSAURI are sample PKCS #11 URIs used for testing HSM
	// Compatibility. Before running tests, copy the contents of the
	// testdata/tokens/ directory to your SoftHSM2 token directory, usually
	// located at /var/lib/softhsm/tokens/, and run `make test-softhsm`
	RSAURI   = "pkcs11:token=SoftHSM2%20Token;id=%03;slot-id=43989470?module-path=/usr/local/lib64/softhsm/libsofthsm2.so&pin-value=1234"
	ECDSAURI = "pkcs11:token=SoftHSM2%20Token;id=%02;slot-id=43989470?module-path=/usr/local/lib64/softhsm/libsofthsm2.so&pin-value=1234"
)

// HSMSignParams represents a set of parameters to a HSM signing operation.
type HSMSignParams struct {
	Opcode      protocol.Op       // The Keyless protocol opcode for this operation
	URI         string            // The PKCS#11 URI of the key to be used for signing
	Opts        crypto.SignerOpts // Options to the signing function
	PayloadSize int               // The size of the payload to be signed
}

var (
	HSMECDSASHA256Params = HSMSignParams{Opcode: protocol.OpECDSASignSHA256, URI: ECDSAURI, Opts: crypto.SHA256, PayloadSize: 32}
	HSMRSASHA512Params   = HSMSignParams{Opcode: protocol.OpRSASignSHA512, URI: RSAURI, Opts: crypto.SHA512, PayloadSize: 64}
)
