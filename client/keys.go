package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"io"

	"github.com/cloudflare/gokeyless"
)

// PrivateKey represents a keyless-backed RSA private key.
type PrivateKey struct {
	public crypto.PublicKey
	ski    gokeyless.SKI
	digest gokeyless.Digest

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
	if len(msg) != opts.HashFunc().Size() {
		return nil, errors.New("input must be hashed message")
	}

	conn, err := key.client.DialAny(key.ski)
	if err != nil {
		return nil, err
	}

	op := signOpFromKeyHash(key, opts.HashFunc())
	if op == gokeyless.OpError {
		return nil, errors.New("invalid key type or hash")
	}
	return conn.KeyOperation(op, msg, key.ski, key.digest)
}

// Decrypt implements the crypto.Decrypter operation for the given key.
func (key *PrivateKey) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	conn, err := key.client.DialAny(key.ski)
	if err != nil {
		return nil, err
	}
	switch opts := opts.(type) {
	case *rsa.PKCS1v15DecryptOptions:
		ptxt, decyptErr := conn.KeyOperation(gokeyless.OpRSADecrypt, msg, key.ski, key.digest)

		// If opts.SessionKeyLen is set, we must perform a variation of
		// rsa.DecryptPKCS1v15SessionKey to ensure the entire operation
		// is performed in constant time regardless of padding errors.
		if l := opts.SessionKeyLen; l > 0 {
			plaintext := make([]byte, l)
			if _, err := io.ReadFull(rand, plaintext); err != nil {
				return nil, err
			}
			valid := subtle.ConstantTimeEq(int32(len(ptxt)), int32(l))
			subtle.ConstantTimeCopy(valid, plaintext, ptxt[:l])
			return plaintext, nil
		}
		// Otherwise, we can just return the error like rsa.DecryptPKCS1v15.
		return ptxt, decyptErr
	default:
		return nil, errors.New("invalid options for Decrypt")
	}
}
