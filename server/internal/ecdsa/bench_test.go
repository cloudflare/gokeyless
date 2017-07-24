package ecdsa

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/cloudflare/gokeyless/internal/test/params"
	"github.com/joshlf/testutil"
)

func benchSplitSignECDSA(b *testing.B, params params.ECDSASignParams) {
	buf := NewRandBuffer(1024, params.Curve)
	for !buf.IsFull() {
		err := buf.Fill(crand.Reader)
		testutil.MustPrefix(b, "could not generate random values", err)
	}

	key, err := ecdsa.GenerateKey(params.Curve, crand.Reader)
	testutil.MustPrefix(b, "could not generate ECDSA key", err)
	payload := make([]byte, params.PayloadSize)
	_, err = io.ReadFull(crand.Reader, payload[:])
	testutil.MustPrefix(b, "could not generate random payload", err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Artificially reset the buffer, making it look full again.
		//
		// We're cheating here by re-using elements because if we pregenerate all
		// b.N elements and then only time this loop, the benchmark runner will
		// treat this test as very fast, and will run it for a very large b.N value,
		// which will make running this benchmark take forever. This is obviously a
		// security disaster, but it shouldn't affect the runtime, which is what
		// we're trying to measure.
		buf.elems = len(buf.buffer)
		Sign(crand.Reader, key, payload, params.Opts, buf)
	}
}

func benchGenRandECDSA(b *testing.B, params params.ECDSASignParams) {
	for i := 0; i < b.N; i++ {
		_, _, err := genRandForSign(crand.Reader, params.Curve)
		testutil.MustPrefix(b, "could not generate random values", err)
	}
}

func BenchmarkSignECDSASHA224(b *testing.B) { benchSplitSignECDSA(b, params.ECDSASHA224Params) }
func BenchmarkSignECDSASHA256(b *testing.B) { benchSplitSignECDSA(b, params.ECDSASHA256Params) }
func BenchmarkSignECDSASHA384(b *testing.B) { benchSplitSignECDSA(b, params.ECDSASHA384Params) }
func BenchmarkSignECDSASHA512(b *testing.B) { benchSplitSignECDSA(b, params.ECDSASHA512Params) }

func BenchmarkGenRandECDSASHA224(b *testing.B) { benchGenRandECDSA(b, params.ECDSASHA224Params) }
func BenchmarkGenRandECDSASHA256(b *testing.B) { benchGenRandECDSA(b, params.ECDSASHA256Params) }
func BenchmarkGenRandECDSASHA384(b *testing.B) { benchGenRandECDSA(b, params.ECDSASHA384Params) }
func BenchmarkGenRandECDSASHA512(b *testing.B) { benchGenRandECDSA(b, params.ECDSASHA512Params) }
