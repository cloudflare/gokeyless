package client

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/protocol"
	"github.com/cloudflare/gokeyless/server"
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

func signOpFromSignerOpts(key *PrivateKey, opts crypto.SignerOpts) protocol.Op {
	if opts, ok := opts.(*rsa.PSSOptions); ok {
		if _, ok := key.Public().(*rsa.PublicKey); !ok {
			return protocol.OpError
		}
		// Keyless only implements RSA-PSS with salt length == hash length,
		// as used in TLS 1.3.  Check that it's what the client is asking,
		// either explicitly or with the magic value.
		if opts.SaltLength != rsa.PSSSaltLengthEqualsHash &&
			opts.SaltLength != opts.Hash.Size() {
			return protocol.OpError
		}
		switch opts.Hash {
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
		if value, ok := rsaCrypto[opts.HashFunc()]; ok {
			return value
		} else {
			return protocol.OpError
		}
	case *ecdsa.PublicKey:
		if value, ok := ecdsaCrypto[opts.HashFunc()]; ok {
			return value
		} else {
			return protocol.OpError
		}
	case ed25519.PublicKey:
		return protocol.OpEd25519Sign
	default:
		return protocol.OpError
	}
}

// PrivateKey represents a keyless-backed RSA/ECDSA private key.
type PrivateKey struct {
	public    crypto.PublicKey
	client    *Client
	ski       protocol.SKI
	clientIP  net.IP
	serverIP  net.IP
	keyserver string
	sni       string
	certID    string

	// We have shove the span context inside PrivateKey because
	// it's used by calling functions on the `crypto.Signer` interface, which don't take ctx as a parameter.
	JaegerSpan []byte
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
			return nil, server.RemoteConfigurationErr{Err: err}
		}

		conn, err := r.Dial(key.client)
		if err != nil {
			return nil, server.RemoteConfigurationErr{Err: err}
		}

		// We explicitly do NOT want to fill in JaegerSpan here, since the remote keyless server
		// will error if it does know how to handle that Tag
		// https://github.com/cloudflare/gokeyless/pull/276 makes it safe to fill it in,
		// but there's no way to know the version of the remote keyserver
		result, err = conn.Conn.DoOperation(ctx, protocol.Operation{
			Opcode:   op,
			Payload:  msg,
			SKI:      key.ski,
			ClientIP: key.clientIP,
			ServerIP: key.serverIP,
			SNI:      key.sni,
			CertID:   key.certID,
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

	// If opts specifies a hash function, then the message is expected to be the
	// length of the output of that hash function.
	if opts.HashFunc() != 0 && len(msg) != opts.HashFunc().Size() {
		return nil, errors.New("input must be hashed message")
	}

	op := signOpFromSignerOpts(key, opts)
	if op == protocol.OpError {
		return nil, errors.New("invalid key type, hash or options")
	}
	return key.execute(ctx, op, msg)
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
