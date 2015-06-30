package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"io"

	"github.com/cloudflare/gokeyless"
)

// PrivateKey represents a keyless-backed RSA private key.
type PrivateKey struct {
	public crypto.PublicKey
	ski    gokeyless.SKI

	client *Client

	crypto.Signer
	crypto.Decrypter
}

// Public returns the public key corresponding to the opaque, private key.
func (key *PrivateKey) Public() crypto.PublicKey {
	return key.public
}

func signOpFromKeyHash(key *PrivateKey, h crypto.Hash) gokeyless.Op {
	switch key.Public().(type) {
	case *rsa.PublicKey:
		switch h {
		case crypto.MD5SHA1:
			return gokeyless.OpRSASignMD5SHA1
		case crypto.SHA1:
			return gokeyless.OpRSASignSHA1
		case crypto.SHA224:
			return gokeyless.OpRSASignSHA224
		case crypto.SHA256:
			return gokeyless.OpRSASignSHA256
		case crypto.SHA384:
			return gokeyless.OpRSASignSHA384
		case crypto.SHA512:
			return gokeyless.OpRSASignSHA512
		default:
			return gokeyless.OpError
		}
	case *ecdsa.PublicKey:
		switch h {
		case crypto.MD5SHA1:
			return gokeyless.OpECDSASignMD5SHA1
		case crypto.SHA1:
			return gokeyless.OpECDSASignSHA1
		case crypto.SHA224:
			return gokeyless.OpECDSASignSHA224
		case crypto.SHA256:
			return gokeyless.OpECDSASignSHA256
		case crypto.SHA384:
			return gokeyless.OpECDSASignSHA384
		case crypto.SHA512:
			return gokeyless.OpECDSASignSHA512
		default:
			return gokeyless.OpError
		}
	default:
		return gokeyless.OpError
	}
}

// Sign implements the crypto.Signer operation for the given key.
func (key *PrivateKey) Sign(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	conn, err := key.client.DialAny(key.ski)
	if err != nil {
		return nil, err
	}

	op := signOpFromKeyHash(key, opts.HashFunc())
	if op == gokeyless.OpError {
		return nil, errors.New("invalid key type or hash")
	}
	return conn.KeyOperation(op, msg, key.ski)
}

// Decrypt implements the crypto.Decrypter operation for the given key.
func (key *PrivateKey) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	conn, err := key.client.DialAny(key.ski)
	if err != nil {
		return nil, err
	}
	return conn.KeyOperation(gokeyless.OpRSADecryptRaw, msg, key.ski)
}
