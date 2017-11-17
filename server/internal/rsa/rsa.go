package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
)

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

func Decrypt(priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	k := (priv.N.BitLen() + 7) / 8
	if k < 11 {
		return nil, rsa.ErrDecryption
	}

	c := new(big.Int).SetBytes(ciphertext)
	m, err := rsaDecryptInt(priv, c)
	if err != nil {
		return nil, err
	}

	return leftPad(m.Bytes(), k), nil
}

// rsaDecryptInt performs an RSA decryption on big.Ints, resulting in a
// plaintext big.Int. RSA blinding is always used.
func rsaDecryptInt(priv *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	// TODO(agl): can we get away with reusing blinds?
	if c.Cmp(priv.N) > 0 {
		err = rsa.ErrDecryption
		return
	}
	if priv.N.Sign() == 0 {
		return nil, rsa.ErrDecryption
	}

	// Blinding enabled. Blinding involves multiplying c by r^e.
	// Then the decryption operation performs (m^e * r^e)^d mod n
	// which equals mr mod n. The factor of r can then be removed
	// by multiplying by the multiplicative inverse of r.
	var r, ir *big.Int

	for {
		r, err = rand.Int(rand.Reader, priv.N)
		if err != nil {
			return
		}
		if r.Cmp(bigZero) == 0 {
			r = bigOne
		}
		var ok bool
		ir, ok = modInverse(r, priv.N)
		if ok {
			break
		}
	}
	bigE := big.NewInt(int64(priv.E))
	rpowe := new(big.Int).Exp(r, bigE, priv.N) // N != 0
	cCopy := new(big.Int).Set(c)
	cCopy.Mul(cCopy, rpowe)
	cCopy.Mod(cCopy, priv.N)
	c = cCopy

	if priv.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		// We have the precalculated values needed for the CRT.
		m = new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
		m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priv.Primes[0])
		}
		m.Mul(m, priv.Precomputed.Qinv)
		m.Mod(m, priv.Primes[0])
		m.Mul(m, priv.Primes[1])
		m.Add(m, m2)

		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			m2.Exp(c, values.Exp, prime)
			m2.Sub(m2, m)
			m2.Mul(m2, values.Coeff)
			m2.Mod(m2, prime)
			if m2.Sign() < 0 {
				m2.Add(m2, prime)
			}
			m2.Mul(m2, values.R)
			m.Add(m, m2)
		}
	}

	// Unblind.
	m.Mul(m, ir)
	m.Mod(m, priv.N)

	return
}

// modInverse returns ia, the inverse of a in the multiplicative group of prime
// order n. It requires that a be a member of the group (i.e. less than n).
func modInverse(a, n *big.Int) (ia *big.Int, ok bool) {
	g := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)
	g.GCD(x, y, a, n)
	if g.Cmp(bigOne) != 0 {
		// In this case, a and n aren't coprime and we cannot calculate
		// the inverse. This happens because the values of n are nearly
		// prime (being the product of two primes) rather than truly
		// prime.
		return
	}

	if x.Cmp(bigOne) < 0 {
		// 0 is not the multiplicative inverse of any element so, if x
		// < 1, then x is negative.
		x.Add(x, n)
	}

	return x, true
}

// leftPad returns a new slice of length size. The contents of input are right
// aligned in the new slice.
func leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)
	copy(out[len(out)-n:], input)
	return
}
