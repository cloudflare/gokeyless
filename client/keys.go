package client

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"encoding"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/protocol"
	"github.com/cloudflare/gokeyless/tracing"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"golang.org/x/crypto/ed25519"
)

var (
	rsaCrypto = map[crypto.Hash]protocol.Op{
		crypto.MD5SHA1: protocol.OpRSASignMD5SHA1,
		crypto.SHA1:    protocol.OpRSASignSHA1,
		crypto.SHA224:  protocol.OpRSASignSHA224,
		crypto.SHA256:  protocol.OpRSASignSHA256,
		crypto.SHA384:  protocol.OpRSASignSHA384,
		crypto.SHA512:  protocol.OpRSASignSHA512,
	}
	ecdsaCrypto = map[crypto.Hash]protocol.Op{
		crypto.MD5SHA1: protocol.OpECDSASignMD5SHA1,
		crypto.SHA1:    protocol.OpECDSASignSHA1,
		crypto.SHA224:  protocol.OpECDSASignSHA224,
		crypto.SHA256:  protocol.OpECDSASignSHA256,
		crypto.SHA384:  protocol.OpECDSASignSHA384,
		crypto.SHA512:  protocol.OpECDSASignSHA512,
	}
)

// mldsaSignOp returns the ML-DSA signing op matching the encoded size of pub,
// or OpError if pub is not a recognized ML-DSA public key.
func mldsaSignOp(pub crypto.PublicKey) protocol.Op {
	var n int
	switch k := pub.(type) {
	case interface{ Bytes() []byte }:
		n = len(k.Bytes())
	case encoding.BinaryMarshaler:
		b, err := k.MarshalBinary()
		if err != nil {
			return protocol.OpError
		}
		n = len(b)
	default:
		return protocol.OpError
	}
	for _, op := range []protocol.Op{protocol.OpMLDSA44Sign, protocol.OpMLDSA65Sign, protocol.OpMLDSA87Sign} {
		if protocol.MLDSAPublicKeySize(op) == n {
			return op
		}
	}
	return protocol.OpError
}

func signOpFromSignerOpts(key *PrivateKey, opts crypto.SignerOpts) protocol.Op {
	if pss, ok := opts.(*rsa.PSSOptions); ok {
		// A typed-nil *PSSOptions panics on HashFunc, so reject it here.
		if pss == nil {
			return protocol.OpError
		}
		if _, ok := key.Public().(*rsa.PublicKey); !ok {
			return protocol.OpError
		}
		// Keyless only implements RSA-PSS with salt length == hash length,
		// as used in TLS 1.3.  Check that it's what the client is asking,
		// either explicitly or with the magic value.
		if pss.SaltLength != rsa.PSSSaltLengthEqualsHash &&
			pss.SaltLength != pss.Hash.Size() {
			return protocol.OpError
		}
		switch pss.Hash {
		case crypto.SHA256:
			return protocol.OpRSAPSSSignSHA256
		case crypto.SHA384:
			return protocol.OpRSAPSSSignSHA384
		case crypto.SHA512:
			return protocol.OpRSAPSSSignSHA512
		default:
			return protocol.OpError
		}
	}
	switch key.Public().(type) {
	case *rsa.PublicKey:
		if opts == nil {
			return protocol.OpError
		}
		if value, ok := rsaCrypto[opts.HashFunc()]; ok {
			return value
		}
		return protocol.OpError
	case *ecdsa.PublicKey:
		if opts == nil {
			return protocol.OpError
		}
		if value, ok := ecdsaCrypto[opts.HashFunc()]; ok {
			return value
		}
		return protocol.OpError
	case ed25519.PublicKey:
		return protocol.OpEd25519Sign
	default:
		// ML-DSA signs the message directly: only nil or crypto.Hash(0) opts.
		if opts != nil && opts != crypto.Hash(0) {
			return protocol.OpError
		}
		return mldsaSignOp(key.Public())
	}
}

// PrivateKey represents a keyless-backed RSA, ECDSA, Ed25519 or ML-DSA private key.
type PrivateKey struct {
	public    crypto.PublicKey
	client    *Client
	ski       protocol.SKI
	clientIP  net.IP
	serverIP  net.IP
	keyserver string
	sni       string
	certID    string
	// certUsage, if set, is sent on every operation for server-side key selection.
	certUsage *protocol.CertUsage

	// We have shove the span context inside PrivateKey because
	// it's used by calling functions on the `crypto.Signer` interface, which don't take ctx as a parameter.
	JaegerSpan       []byte
	complianceRegion protocol.ComplianceRegion
}

// Public returns the public key corresponding to the opaque private key.
func (key *PrivateKey) Public() crypto.PublicKey {
	return key.public
}

// execute performs an opaque cryptographic operation on a server associated
// with the key.
func (key *PrivateKey) execute(ctx context.Context, op protocol.Op, msg []byte) ([]byte, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "PrivateKey.execute")
	defer span.Finish()
	var result *protocol.Operation
	// retry once if connection returned by remote Dial is problematic.
	for attempts := 2; attempts > 0; attempts-- {
		r, err := key.client.getRemote(key.keyserver)
		if err != nil {
			return nil, protocol.RemoteConfigurationErr{Err: err}
		}

		conn, err := r.Dial(key.client)
		if err != nil {
			return nil, protocol.RemoteConfigurationErr{Err: err}
		}

		// We explicitly do NOT want to fill in JaegerSpan here, since the remote keyless server
		// will error if it does know how to handle that Tag
		// https://github.com/cloudflare/gokeyless/pull/276 makes it safe to fill it in,
		// but there's no way to know the version of the remote keyserver
		result, err = conn.Conn.DoOperation(ctx, protocol.Operation{
			Opcode:           op,
			Payload:          msg,
			SKI:              key.ski,
			ClientIP:         key.clientIP,
			ServerIP:         key.serverIP,
			SNI:              key.sni,
			CertID:           key.certID,
			CertUsage:        key.certUsage,
			ComplianceRegion: key.complianceRegion,
		})
		if err != nil {
			conn.Close()
			// not the last attempt, log error and retry
			if attempts > 1 {
				log.Info("failed remote operation:", err)
				log.Infof("retry new connection")
				continue
			}
			return nil, err
		}
		conn.KeepAlive()
		break
	}

	if result.Opcode != protocol.OpResponse {
		if result.Opcode == protocol.OpError {
			return nil, result.GetError()
		}
		return nil, fmt.Errorf("wrong response opcode: %v", result.Opcode)
	}

	if len(result.Payload) == 0 {
		return nil, errors.New("empty payload")
	}

	return result.Payload, nil
}

// Sign implements the crypto.Signer operation for the given key.
func (key *PrivateKey) Sign(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	spanCtx, err := tracing.SpanContextFromBinary(key.JaegerSpan)
	if err != nil {
		log.Errorf("failed to extract span: %v", err)
	}
	span, ctx := opentracing.StartSpanFromContext(context.Background(), "client: PrivateKey.Sign", ext.RPCServerOption(spanCtx))
	defer span.Finish()

	op := signOpFromSignerOpts(key, opts)
	if op == protocol.OpError {
		return nil, errors.New("invalid key type, hash or options")
	}

	if op.IsMLDSASign() {
		// ML-DSA keys only sign TLS 1.3 CertificateVerify inputs; reject others locally.
		if !protocol.ValidTLS13ServerCertificateVerify(msg) {
			return nil, errors.New("ML-DSA input must be a TLS 1.3 server CertificateVerify message")
		}
	} else {
		if opts == nil {
			return nil, errors.New("signer options are required")
		}
		// If opts specifies a hash function, then the message is expected to be the
		// length of the output of that hash function.
		if opts.HashFunc() != 0 && len(msg) != opts.HashFunc().Size() {
			return nil, errors.New("input must be hashed message")
		}
	}

	sig, err := key.execute(ctx, op, msg)
	if err != nil {
		return nil, err
	}
	if op.IsMLDSASign() && len(sig) != protocol.MLDSASignatureSize(op) {
		return nil, fmt.Errorf("unexpected ML-DSA signature length %d", len(sig))
	}
	return sig, nil
}

// Decrypter implements the Decrypt method on a PrivateKey.
type Decrypter struct {
	PrivateKey
}

// Decrypt implements the crypto.Decrypter operation for the given key.
func (key *Decrypter) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	spanCtx, err := tracing.SpanContextFromBinary(key.JaegerSpan)
	if err != nil {
		log.Errorf("failed to extract span: %v", err)
	}
	span, ctx := opentracing.StartSpanFromContext(context.Background(), "client: Decrypter.Decrypt", ext.RPCServerOption(spanCtx))
	defer span.Finish()
	opts1v15, ok := opts.(*rsa.PKCS1v15DecryptOptions)
	if opts != nil && !ok {
		return nil, errors.New("invalid options for Decrypt")
	}

	ptxt, err := key.execute(ctx, protocol.OpRSADecrypt, msg)
	if err != nil {
		return nil, err
	}

	if ok {
		if l := opts1v15.SessionKeyLen; l > 0 {
			key := make([]byte, opts1v15.SessionKeyLen)
			if _, err := io.ReadFull(rand, key); err != nil {
				return nil, err
			} else if err = stripPKCS1v15SessionKey(ptxt, key); err != nil {
				return nil, err
			}
			return key, nil
		}
		return stripPKCS1v15(ptxt)
	}
	return ptxt, nil
}

func stripPKCS1v15(em []byte) ([]byte, error) {
	valid, index := parsePKCS1v15(em)
	if valid == 0 {
		return nil, rsa.ErrDecryption
	}
	return em[index:], nil
}

func stripPKCS1v15SessionKey(em, key []byte) error {
	if len(em)-(len(key)+3+8) < 0 {
		return rsa.ErrDecryption
	}

	valid, index := parsePKCS1v15(em)
	valid &= subtle.ConstantTimeEq(int32(len(em)-index), int32(len(key)))
	subtle.ConstantTimeCopy(valid, key, em[len(em)-len(key):])
	return nil
}

func parsePKCS1v15(em []byte) (valid, index int) {
	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)
	secondByteIsTwo := subtle.ConstantTimeByteEq(em[1], 2)

	// The remainder of the plaintext must be a string of non-zero random
	// octets, followed by a 0, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the zero.
	//   index: the offset of the first zero byte.
	lookingForIndex := 1

	for i := 2; i < len(em); i++ {
		equals0 := subtle.ConstantTimeByteEq(em[i], 0)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals0, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals0, 0, lookingForIndex)
	}

	// The PS padding must be at least 8 bytes long, and it starts two
	// bytes into em.
	validPS := subtle.ConstantTimeLessOrEq(2+8, index)

	valid = firstByteIsZero & secondByteIsTwo & (^lookingForIndex & 1) & validPS
	index = subtle.ConstantTimeSelect(valid, index+1, 0)
	return
}
