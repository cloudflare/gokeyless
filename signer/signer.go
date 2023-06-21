package signer

import (
	"context"
	"crypto"
	"io"
)

// CtxSigner wraps crypto.Signer but with context
// Signers that involve a remote trip (such as to another keyless instance)
// should use the ctx parameter in their implementation, and should NOT use WrappedSigner
type CtxSigner interface {
	Public() crypto.PublicKey
	Sign(ctx context.Context, rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
}

// WrappedSigner is a wrapper for for signers that don't need or support context
// for example, signing with a keypair from disk, or from a HSM
type WrappedSigner struct {
	Inner crypto.Signer
}

func (w *WrappedSigner) Public() crypto.PublicKey {
	return w.Inner.Public()
}
func (w *WrappedSigner) Sign(_ context.Context, rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return w.Inner.Sign(rand, digest, opts)
}

func WrapSigner(s crypto.Signer) CtxSigner {
	return &WrappedSigner{
		Inner: s,
	}

}
