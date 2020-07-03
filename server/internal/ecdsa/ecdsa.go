package ecdsa

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
)

type rand struct {
	kInv, r *big.Int
}

// NOTE: This buffer is designed to ensure that, regardless of how code outside
// of this package uses these types and methods, no random value will ever be
// used more than once in an ECDSA signature. When modifying this code, be VERY
// CAREFUL that this behavior is maintained.

// A RandProvider is capable of producing random values for use in ECDSA
// signatures. It cannot be implemented by types outside of this package.
type RandProvider interface {
	gen(rand io.Reader) (kInv, rr *big.Int, err error)
	curve() elliptic.Curve
}

// A RandBuffer is a buffer to store pre-computed random values for use in ECDSA
// signatures.
//
// RandBuffers are NOT safe for concurrent use, and doing so introduces a
// serious security risk!
//
// RandBuffers are not safe to be copied.
type RandBuffer struct {
	buffer []rand
	elems  int
	crv    elliptic.Curve
}

var _ RandProvider = &RandBuffer{}

// NewRandBuffer initializes a new RandBuffer with the given capacity which
// generates randomness for the given curve.
func NewRandBuffer(cap int, curve elliptic.Curve) *RandBuffer {
	return &RandBuffer{buffer: make([]rand, cap), crv: curve}
}

// Size returns the number of elements in the buffer.
func (r *RandBuffer) Size() int {
	return r.elems
}

// IsFull returns true if the buffer is full.
func (r *RandBuffer) IsFull() bool {
	return r.elems == len(r.buffer)
}

// Fill generates and adds a single set of random values to the buffer. If
// r is currently full, Fill is a no-op.
func (r *RandBuffer) Fill(rnd io.Reader) error {
	if r.IsFull() {
		return nil
	}

	kInv, rr, err := genRandForSign(rnd, r.crv)
	if err != nil {
		return err
	}
	r.buffer[r.elems] = rand{kInv: kInv, r: rr}
	r.elems++
	return nil
}

func (r *RandBuffer) gen(rand io.Reader) (kInv, rr *big.Int, err error) {
	if r.elems == 0 {
		return genRandForSign(rand, r.crv)
	}
	ret := r.buffer[r.elems-1]
	r.elems--
	return ret.kInv, ret.r, nil
}

func (r *RandBuffer) curve() elliptic.Curve { return r.crv }

// A SyncRandBuffer is a buffer to store pre-computed random values for use in
// ECDSA signatures.
//
// Unlike RandBuffers, SyncRandBuffers are safe for concurrent use.
type SyncRandBuffer struct {
	buf chan rand
	crv elliptic.Curve
}

var _ RandProvider = &SyncRandBuffer{}

// NewSyncRandBuffer initializes a new SyncRandBuffer with the given capacity
// which generates randomness for the given curve.
func NewSyncRandBuffer(cap int, curve elliptic.Curve) *SyncRandBuffer {
	return &SyncRandBuffer{buf: make(chan rand, cap), crv: curve}
}

// Fill generates and adds a single set of random values to the buffer. If s is
// currently full, Fill will block until there is room for the generated value
// to be stored or if ctx is canceled.
func (s *SyncRandBuffer) Fill(ctx context.Context, rnd io.Reader) error {
	kInv, r, err := genRandForSign(rnd, s.crv)
	if err != nil {
		return err
	}
	select {
	case s.buf <- rand{kInv: kInv, r: r}:
	case <-ctx.Done():
	}
	return nil
}

func (s *SyncRandBuffer) gen(rnd io.Reader) (kInv, rr *big.Int, err error) {
	select {
	case r := <-s.buf:
		return r.kInv, r.r, nil
	default:
		return genRandForSign(rnd, s.crv)
	}
}

func (s *SyncRandBuffer) curve() elliptic.Curve { return s.crv }

// Sign computes an ECDSA signature. Other than the provider argument, its usage
// is identical to the usage of crypto/ecdsa.PrivateKey.Sign from the standard
// library.
//
// Sign will use buffer to provide it the randomness that it needs, although if
// the buffer runs out of randomness before Sign is finished, it will fall back
// on generating the randomness directly. A single call to Sign may consume any
// number of elements from the buffer - callers should not assume that only a
// single element - or any other fixed number of elements - will be consumed.
func Sign(rand io.Reader, priv *ecdsa.PrivateKey, msg []byte, opts crypto.SignerOpts, provider RandProvider) ([]byte, error) {
	r, s, err := sign(rand, priv, msg, provider)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ecdsaSignature{r, s})
}

type ecdsaSignature struct {
	R, S *big.Int
}

func sign(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte, provider RandProvider) (r, s *big.Int, err error) {
	c := priv.Curve
	if c != provider.curve() {
		panic("mismatched curves")
	}

	N := c.Params().N
	var kInv *big.Int
	for {
		kInv, r, err = provider.gen(rand)
		if err != nil {
			return nil, nil, err
		}

		e := hashToInt(hash, c)
		s = new(big.Int).Mul(priv.D, r)
		s.Add(s, e)
		s.Mul(s, kInv)
		s.Mod(s, N) // N != 0
		if s.Sign() != 0 {
			break
		}
	}

	return
}

func genRandForSign(rand io.Reader, curve elliptic.Curve) (kInv, r *big.Int, err error) {
	// In the Go standard library's ECDSA implementation, they mix together the
	// private key, the hash to be signed, and up to 32 bytes of random data to
	// compute the key for the CSPRNG. We don't have access to the private key or
	// the hash, but if rand is a cryptographically secure source of randomness,
	// that doesn't matter - the CSPRNG's output will still be cryptographically
	// secure.
	var key [32]byte
	_, err = io.ReadFull(rand, key[:])
	if err != nil {
		return nil, nil, err
	}

	// Create an AES-CTR instance to use as a CSPRNG.
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, err
	}

	// Create a CSPRNG that xors a stream of zeros with
	// the output of the AES-CTR instance.
	csprng := cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}

	N := curve.Params().N
	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}
	for {
		k, err := randFieldElement(curve, csprng)
		if err != nil {
			r = nil
			return nil, nil, err
		}

		if in, ok := curve.(invertible); ok {
			kInv = in.Inverse(k)
		} else {
			kInv = fermatInverse(k, N) // N != 0
		}

		r, _ = curve.ScalarBaseMult(k.Bytes())
		r.Mod(r, N)
		if r.Sign() != 0 {
			break
		}
	}
	return kInv, r, nil
}

/*
	ECDSA Internals. The code from here down is copied verbatim from the Go
  standard library.
*/

const (
	aesIV = "IV for ECDSA CTR"
)

var errZeroParam = errors.New("zero parameter")

var one = new(big.Int).SetInt64(1)

// randFieldElement returns a random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// hashToInt converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method.
// This has better constant-time properties than Euclid's method (implemented
// in math/big.Int.ModInverse) although math/big itself isn't strictly
// constant-time so it's not perfect.
func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}

// A invertible implements fast inverse mod Curve.Params().N
type invertible interface {
	// Inverse returns the inverse of k in GF(P)
	Inverse(k *big.Int) *big.Int
}

type zr struct {
	io.Reader
}

// Read replaces the contents of dst with zeros.
func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}
