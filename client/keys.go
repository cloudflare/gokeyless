package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/internal/protocol"
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
}

// Public returns the public key corresponding to the opaque private key.
func (key *PrivateKey) Public() crypto.PublicKey {
	return key.public
}

// execute performs an opaque cryptographic operation on a server associated
// with the key.
func (key *PrivateKey) execute(op protocol.Op, msg []byte) ([]byte, error) {
	var result *protocol.Operation
	// retry once if connection returned by remote Dial is problematic.
	for attempts := 2; attempts > 0; attempts-- {
		r, err := key.client.getRemote(key.keyserver)
		if err != nil {
			return nil, err
		}

		conn, err := r.Dial(key.client)
		if err != nil {
			return nil, err
		}

		result, err = conn.Conn.DoOperation(protocol.Operation{
			Opcode:   op,
			Payload:  msg,
			SKI:      key.ski,
			ClientIP: key.clientIP,
			ServerIP: key.serverIP,
			SNI:      key.sni,
		})
		if err != nil {
			conn.Close()
			// not the last attempt, log error and retry
			if attempts > 1 {
				log.Info("failed remote operation:", err)
				log.Infof("retry new connction")
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
	if len(msg) != opts.HashFunc().Size() {
		return nil, errors.New("input must be hashed message")
	}

	op := signOpFromSignerOpts(key, opts)
	if op == protocol.OpError {
		return nil, errors.New("invalid key type, hash or options")
	}
	return key.execute(op, msg)
}

// Decrypter implements the Decrypt method on a PrivateKey.
type Decrypter struct {
	PrivateKey
}

// Decrypt implements the crypto.Decrypter operation for the given key.
func (key *Decrypter) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	opts1v15, ok := opts.(*rsa.PKCS1v15DecryptOptions)
	if opts != nil && !ok {
		return nil, errors.New("invalid options for Decrypt")
	}

	ptxt, err := key.execute(protocol.OpRSADecrypt, msg)
	if err != nil {
		return nil, err
	}

	if ok {
		// If opts.SessionKeyLen is set, we must perform a variation of
		// rsa.DecryptPKCS1v15SessionKey to ensure the entire operation
		// is performed in constant time regardless of padding errors.
		if l := opts1v15.SessionKeyLen; l > 0 {
			plaintext := make([]byte, l)
			if _, err := io.ReadFull(rand, plaintext); err != nil {
				return nil, err
			}
			valid := subtle.ConstantTimeEq(int32(len(ptxt)), int32(l))
			v2 := subtle.ConstantTimeLessOrEq(l, len(ptxt))
			l2 := subtle.ConstantTimeSelect(v2, l, len(ptxt))
			subtle.ConstantTimeCopy(valid, plaintext[:l2], ptxt[:l2])
			return plaintext, nil
		}
	}
	return ptxt, nil
}
