//go:build pkcs11
// +build pkcs11

package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"io"
	"os"
	"runtime"
	"sync"
	"testing"

	"github.com/cloudflare/gokeyless/internal/rfc7512"
	"github.com/cloudflare/gokeyless/internal/test/params"
	"github.com/joshlf/testutil"
)

var testSoftHSM bool

func init() {
	flag.BoolVar(&testSoftHSM, "softhsm2", false, "whether to test against SoftHSM2")
	if os.Getenv("TEST_SOFT_HSM") == "true" {
		testSoftHSM = true
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

// mustReadFull tries to read from r until b is fully populated, calling
// tb.Fatal on failure.
func mustReadFull(tb testutil.TB, r io.Reader, b []byte) {
	_, err := io.ReadFull(r, b)
	testutil.MustPrefix(tb, "could not perform full read", err)
}

func benchSign(b *testing.B, key crypto.Signer, rnd io.Reader, payload []byte, opts crypto.SignerOpts) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := key.Sign(rnd, payload, opts)
		testutil.MustPrefix(b, "could not create signature", err)
	}
}

func benchSignParallel(b *testing.B, key crypto.Signer, rnd io.Reader, payload []byte, opts crypto.SignerOpts) {
	// The barrier is used to ensure that goroutines only start running once we
	// release them.
	var barrier, wg sync.WaitGroup
	barrier.Add(1)
	wg.Add(runtime.NumCPU())
	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			barrier.Wait()
			for i := 0; i < b.N; i++ {
				_, err := key.Sign(rnd, payload, opts)
				testutil.MustPrefix(b, "could not create signature", err)
			}
			wg.Done()
		}()
	}

	b.ResetTimer()
	barrier.Done()
	wg.Wait()
}

type countingReader int

func (c *countingReader) Read(b []byte) (n int, err error) {
	n, err = rand.Read(b)
	if err != nil {
		panic(err)
	}
	*c += countingReader(n)
	return n, err
}

// benchRandFor calls op once with a custom reader to determine how many bytes
// of randomness are requested. Then, it benchmarks reading that many bytes from
// "crypto/rand".Reader.
func benchRandFor(b *testing.B, op func(rnd io.Reader)) {
	var c countingReader
	op(&c)
	buf := make([]byte, int(c))
	b.SetBytes(int64(c))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := io.ReadFull(rand.Reader, buf)
		testutil.MustPrefix(b, "could not read crypto/rand.Reader", err)
	}
}

// benchRandParallelFor is like benchRandFor, but it spawns one goroutine per
// CPU core in order to benchmark the effects of contention on the /dev/urandom
// subsystem. It reports the speed for a single operation (in other words, if
// four cores are used, it will not report a number four times as high as if
// one core were used, but rather (in the highest-performance case) the same
// number).
func benchRandParallelFor(b *testing.B, op func(rnd io.Reader)) {
	var c countingReader
	op(&c)
	b.SetBytes(int64(c))

	// The barrier is used to ensure that goroutines only start running once we
	// release them.
	var barrier, wg sync.WaitGroup
	barrier.Add(1)
	wg.Add(runtime.NumCPU())
	for i := 0; i < runtime.NumCPU(); i++ {
		buf := make([]byte, int(c))
		go func(buf []byte) {
			barrier.Wait()
			for i := 0; i < b.N; i++ {
				_, err := io.ReadFull(rand.Reader, buf)
				testutil.MustPrefix(b, "could not read crypto/rand.Reader", err)
			}
			wg.Done()
		}(buf)
	}

	b.ResetTimer()
	barrier.Done()
	wg.Wait()
}

// benchRandForSignRSA is an RSA signature-specific wrapper around benchRandFor.
func benchRandForSignRSA(b *testing.B, params params.RSASignParams) {
	key, payload := prepareRSASigner(b, 2, 2048, params.PayloadSize, true)
	op := func(rnd io.Reader) { key.Sign(rnd, payload, params.Opts) }
	benchRandFor(b, op)
}

// benchRandParallelForSignRSA is an RSA signature-specific wrapper around
// benchRandFor.
func benchRandParallelForSignRSA(b *testing.B, params params.RSASignParams) {
	key, payload := prepareRSASigner(b, 2, 2048, params.PayloadSize, true)
	op := func(rnd io.Reader) { key.Sign(rnd, payload, params.Opts) }
	benchRandParallelFor(b, op)
}

func benchSignRSA(b *testing.B, params params.RSASignParams, primes int, precompute bool) {
	key, payload := prepareRSASigner(b, primes, 2048, params.PayloadSize, precompute)
	benchSign(b, key, rand.Reader, payload[:], params.Opts)
}

func benchSignParallelRSA(b *testing.B, params params.RSASignParams) {
	key, payload := prepareRSASigner(b, 2, 2048, params.PayloadSize, true)
	benchSignParallel(b, key, rand.Reader, payload[:], params.Opts)
}

// prepareRSASigner performs the boilerplate of generating values needed to
// benchmark RSA signatures.
func prepareRSASigner(b *testing.B, primes, bits int, payloadsize int, precompute bool) (key crypto.Signer, payload []byte) {
	k, err := rsa.GenerateMultiPrimeKey(rand.Reader, primes, bits)
	testutil.MustPrefix(b, "could not generate RSA key", err)
	if !precompute {
		k.Precomputed = rsa.PrecomputedValues{}
	}
	payload = make([]byte, payloadsize)
	mustReadFull(b, rand.Reader, payload[:])
	return k, payload
}

// benchRandForSignECDSA is an ECDSA signature-specific wrapper around benchRandFor.
func benchRandForSignECDSA(b *testing.B, params params.ECDSASignParams) {
	key, payload := prepareECDSASigner(b, params.Curve, params.PayloadSize)
	op := func(rnd io.Reader) { key.Sign(rnd, payload, params.Opts) }
	benchRandFor(b, op)
}

// benchRandParallelForSignECDSA is an ECDSA signature-specific wrapper around
// benchRandParallelFor.
func benchRandParallelForSignECDSA(b *testing.B, params params.ECDSASignParams) {
	key, payload := prepareECDSASigner(b, params.Curve, params.PayloadSize)
	op := func(rnd io.Reader) { key.Sign(rnd, payload, params.Opts) }
	benchRandParallelFor(b, op)
}

func benchSignECDSA(b *testing.B, params params.ECDSASignParams) {
	key, payload := prepareECDSASigner(b, params.Curve, params.PayloadSize)
	benchSign(b, key, rand.Reader, payload[:], params.Opts)
}

func benchSignParallelECDSA(b *testing.B, params params.ECDSASignParams) {
	key, payload := prepareECDSASigner(b, params.Curve, params.PayloadSize)
	benchSignParallel(b, key, rand.Reader, payload[:], params.Opts)
}

// prepareECDSASigner performs the boilerplate of generating values needed to
// benchmark ECDSA signatures.
func prepareECDSASigner(b *testing.B, curve elliptic.Curve, payloadsize int) (key crypto.Signer, payload []byte) {
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	testutil.MustPrefix(b, "could not generate ECDSA key", err)
	payload = make([]byte, payloadsize)
	mustReadFull(b, rand.Reader, payload[:])
	return k, payload
}

func benchHSMSign(b *testing.B, params params.HSMSignParams) {
	pk11uri, _ := rfc7512.ParsePKCS11URI(params.URI)
	key, payload := prepareHSMSigner(b, pk11uri, params.PayloadSize)
	benchSign(b, key, rand.Reader, payload[:], params.Opts)
}

func benchHSMSignParallel(b *testing.B, params params.HSMSignParams) {
	pk11uri, _ := rfc7512.ParsePKCS11URI(params.URI)
	key, payload := prepareHSMSigner(b, pk11uri, params.PayloadSize)
	benchSignParallel(b, key, rand.Reader, payload[:], params.Opts)
}

// prepareHSMSigner performs the boilerplate of generating values needed to
// benchmark signatures on a Hardware Security Module.
func prepareHSMSigner(b *testing.B, pk11uri *rfc7512.PKCS11URI, payloadsize int) (key crypto.Signer, payload []byte) {
	k, err := rfc7512.LoadPKCS11Signer(pk11uri)
	testutil.MustPrefix(b, "could not load PKCS11 key", err)
	payload = make([]byte, payloadsize)
	mustReadFull(b, rand.Reader, payload[:])
	return k, payload
}

func BenchmarkCryptoRand(b *testing.B) {
	buf := make([]byte, b.N)
	b.SetBytes(1)
	b.ResetTimer()
	io.ReadFull(rand.Reader, buf)
}

func BenchmarkSignRSAMD5SHA1(b *testing.B)      { benchSignRSA(b, params.RSAMD5SHA1Params, 2, true) }
func BenchmarkSignRSAMD5SHA1Multi(b *testing.B) { benchSignRSA(b, params.RSAMD5SHA1Params, 3, true) }
func BenchmarkSignRSAMD5SHA1NotPrecomputed(b *testing.B) {
	benchSignRSA(b, params.RSAMD5SHA1Params, 2, false)
}
func BenchmarkSignRSASHA1(b *testing.B)      { benchSignRSA(b, params.RSASHA1Params, 2, true) }
func BenchmarkSignRSASHA1Multi(b *testing.B) { benchSignRSA(b, params.RSASHA1Params, 3, true) }
func BenchmarkSignRSASHA1NotPrecomputed(b *testing.B) {
	benchSignRSA(b, params.RSASHA1Params, 2, false)
}
func BenchmarkSignRSASHA224(b *testing.B)      { benchSignRSA(b, params.RSASHA224Params, 2, true) }
func BenchmarkSignRSASHA224Multi(b *testing.B) { benchSignRSA(b, params.RSASHA224Params, 3, true) }
func BenchmarkSignRSASHA224NotPrecomputed(b *testing.B) {
	benchSignRSA(b, params.RSASHA224Params, 2, false)
}
func BenchmarkSignRSASHA256(b *testing.B)      { benchSignRSA(b, params.RSASHA256Params, 2, true) }
func BenchmarkSignRSASHA256Multi(b *testing.B) { benchSignRSA(b, params.RSASHA256Params, 3, true) }
func BenchmarkSignRSASHA256NotPrecomputed(b *testing.B) {
	benchSignRSA(b, params.RSASHA256Params, 2, false)
}
func BenchmarkSignRSASHA384(b *testing.B)      { benchSignRSA(b, params.RSASHA384Params, 2, true) }
func BenchmarkSignRSASHA384Multi(b *testing.B) { benchSignRSA(b, params.RSASHA384Params, 3, true) }
func BenchmarkSignRSASHA384NotPrecomputed(b *testing.B) {
	benchSignRSA(b, params.RSASHA384Params, 2, false)
}
func BenchmarkSignRSASHA512(b *testing.B)      { benchSignRSA(b, params.RSASHA512Params, 2, true) }
func BenchmarkSignRSASHA512Multi(b *testing.B) { benchSignRSA(b, params.RSASHA512Params, 3, true) }
func BenchmarkSignRSASHA512NotPrecomputed(b *testing.B) {
	benchSignRSA(b, params.RSASHA512Params, 2, false)
}
func BenchmarkSignRSAPSSSHA256(b *testing.B) { benchSignRSA(b, params.RSAPSSSHA256Params, 2, true) }
func BenchmarkSignRSAPSSSHA256Multi(b *testing.B) {
	benchSignRSA(b, params.RSAPSSSHA256Params, 3, true)
}
func BenchmarkSignRSAPSSSHA256NotPrecomputed(b *testing.B) {
	benchSignRSA(b, params.RSAPSSSHA256Params, 2, false)
}
func BenchmarkSignRSAPSSSHA384(b *testing.B) { benchSignRSA(b, params.RSAPSSSHA384Params, 2, true) }
func BenchmarkSignRSAPSSSHA384Multi(b *testing.B) {
	benchSignRSA(b, params.RSAPSSSHA384Params, 3, true)
}
func BenchmarkSignRSAPSSSHA384NotPrecomputed(b *testing.B) {
	benchSignRSA(b, params.RSAPSSSHA384Params, 2, false)
}
func BenchmarkSignRSAPSSSHA512(b *testing.B) { benchSignRSA(b, params.RSAPSSSHA512Params, 2, true) }
func BenchmarkSignRSAPSSSHA512Multi(b *testing.B) {
	benchSignRSA(b, params.RSAPSSSHA512Params, 3, true)
}
func BenchmarkSignRSAPSSSHA512NotPrecomputed(b *testing.B) {
	benchSignRSA(b, params.RSAPSSSHA512Params, 2, false)
}

func BenchmarkSignECDSASHA224(b *testing.B) { benchSignECDSA(b, params.ECDSASHA224Params) }
func BenchmarkSignECDSASHA256(b *testing.B) { benchSignECDSA(b, params.ECDSASHA256Params) }
func BenchmarkSignECDSASHA384(b *testing.B) { benchSignECDSA(b, params.ECDSASHA384Params) }
func BenchmarkSignECDSASHA512(b *testing.B) { benchSignECDSA(b, params.ECDSASHA512Params) }

func BenchmarkSignParallelRSAMD5SHA1(b *testing.B) { benchSignParallelRSA(b, params.RSAMD5SHA1Params) }
func BenchmarkSignParallelRSASHA1(b *testing.B)    { benchSignParallelRSA(b, params.RSASHA1Params) }
func BenchmarkSignParallelRSASHA224(b *testing.B)  { benchSignParallelRSA(b, params.RSASHA224Params) }
func BenchmarkSignParallelRSASHA256(b *testing.B)  { benchSignParallelRSA(b, params.RSASHA256Params) }
func BenchmarkSignParallelRSASHA384(b *testing.B)  { benchSignParallelRSA(b, params.RSASHA384Params) }
func BenchmarkSignParallelRSASHA512(b *testing.B)  { benchSignParallelRSA(b, params.RSASHA512Params) }
func BenchmarkSignParallelRSAPSSSHA256(b *testing.B) {
	benchSignParallelRSA(b, params.RSAPSSSHA256Params)
}
func BenchmarkSignParallelRSAPSSSHA384(b *testing.B) {
	benchSignParallelRSA(b, params.RSAPSSSHA384Params)
}
func BenchmarkSignParallelRSAPSSSHA512(b *testing.B) {
	benchSignParallelRSA(b, params.RSAPSSSHA512Params)
}
func BenchmarkSignParallelECDSASHA224(b *testing.B) {
	benchSignParallelECDSA(b, params.ECDSASHA224Params)
}
func BenchmarkSignParallelECDSASHA256(b *testing.B) {
	benchSignParallelECDSA(b, params.ECDSASHA256Params)
}
func BenchmarkSignParallelECDSASHA384(b *testing.B) {
	benchSignParallelECDSA(b, params.ECDSASHA384Params)
}
func BenchmarkSignParallelECDSASHA512(b *testing.B) {
	benchSignParallelECDSA(b, params.ECDSASHA512Params)
}

func BenchmarkRandForSignRSAMD5SHA1(b *testing.B) { benchRandForSignRSA(b, params.RSAMD5SHA1Params) }
func BenchmarkRandForSignRSASHA1(b *testing.B)    { benchRandForSignRSA(b, params.RSASHA1Params) }
func BenchmarkRandForSignRSASHA224(b *testing.B)  { benchRandForSignRSA(b, params.RSASHA224Params) }
func BenchmarkRandForSignRSASHA256(b *testing.B)  { benchRandForSignRSA(b, params.RSASHA256Params) }
func BenchmarkRandForSignRSASHA384(b *testing.B)  { benchRandForSignRSA(b, params.RSASHA384Params) }
func BenchmarkRandForSignRSASHA512(b *testing.B)  { benchRandForSignRSA(b, params.RSASHA512Params) }
func BenchmarkRandForSignRSAPSSSHA256(b *testing.B) {
	benchRandForSignRSA(b, params.RSAPSSSHA256Params)
}
func BenchmarkRandForSignRSAPSSSHA384(b *testing.B) {
	benchRandForSignRSA(b, params.RSAPSSSHA384Params)
}
func BenchmarkRandForSignRSAPSSSHA512(b *testing.B) {
	benchRandForSignRSA(b, params.RSAPSSSHA512Params)
}
func BenchmarkRandForSignECDSASHA224(b *testing.B) {
	benchRandForSignECDSA(b, params.ECDSASHA224Params)
}
func BenchmarkRandForSignECDSASHA256(b *testing.B) {
	benchRandForSignECDSA(b, params.ECDSASHA256Params)
}
func BenchmarkRandForSignECDSASHA384(b *testing.B) {
	benchRandForSignECDSA(b, params.ECDSASHA384Params)
}
func BenchmarkRandForSignECDSASHA512(b *testing.B) {
	benchRandForSignECDSA(b, params.ECDSASHA512Params)
}

func BenchmarkRandParallelForSignRSAMD5SHA1(b *testing.B) {
	benchRandParallelForSignRSA(b, params.RSAMD5SHA1Params)
}
func BenchmarkRandParallelForSignRSASHA1(b *testing.B) {
	benchRandParallelForSignRSA(b, params.RSASHA1Params)
}
func BenchmarkRandParallelForSignRSASHA224(b *testing.B) {
	benchRandParallelForSignRSA(b, params.RSASHA224Params)
}
func BenchmarkRandParallelForSignRSASHA256(b *testing.B) {
	benchRandParallelForSignRSA(b, params.RSASHA256Params)
}
func BenchmarkRandParallelForSignRSASHA384(b *testing.B) {
	benchRandParallelForSignRSA(b, params.RSASHA384Params)
}
func BenchmarkRandParallelForSignRSASHA512(b *testing.B) {
	benchRandParallelForSignRSA(b, params.RSASHA512Params)
}
func BenchmarkRandParallelForSignRSAPSSSHA256(b *testing.B) {
	benchRandParallelForSignRSA(b, params.RSAPSSSHA256Params)
}
func BenchmarkRandParallelForSignRSAPSSSHA384(b *testing.B) {
	benchRandParallelForSignRSA(b, params.RSAPSSSHA384Params)
}
func BenchmarkRandParallelForSignRSAPSSSHA512(b *testing.B) {
	benchRandParallelForSignRSA(b, params.RSAPSSSHA512Params)
}
func BenchmarkRandParallelForSignECDSASHA224(b *testing.B) {
	benchRandParallelForSignECDSA(b, params.ECDSASHA224Params)
}
func BenchmarkRandParallelForSignECDSASHA256(b *testing.B) {
	benchRandParallelForSignECDSA(b, params.ECDSASHA256Params)
}
func BenchmarkRandParallelForSignECDSASHA384(b *testing.B) {
	benchRandParallelForSignECDSA(b, params.ECDSASHA384Params)
}
func BenchmarkRandParallelForSignECDSASHA512(b *testing.B) {
	benchRandParallelForSignECDSA(b, params.ECDSASHA512Params)
}

func BenchmarkHSMSignRSASHA512(b *testing.B) {
	if !testSoftHSM {
		b.Skip("skipping test; -softhsm2 flag is not set")
	}
	benchHSMSign(b, params.HSMRSASHA512Params)
}
func BenchmarkHSMSignECDSASHA256(b *testing.B) {
	if !testSoftHSM {
		b.Skip("skipping test; -softhsm2 flag is not set")
	}
	benchHSMSign(b, params.HSMECDSASHA256Params)
}

func BenchmarkHSMSignParallelRSASHA512(b *testing.B) {
	if !testSoftHSM {
		b.Skip("skipping test; -softhsm2 flag is not set")
	}
	benchHSMSignParallel(b, params.HSMRSASHA512Params)
}
func BenchmarkHSMSignParallelECDSASHA256(b *testing.B) {
	if !testSoftHSM {
		b.Skip("skipping test; -softhsm2 flag is not set")
	}
	benchHSMSignParallel(b, params.HSMECDSASHA256Params)
}
