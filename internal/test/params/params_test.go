package params

import (
	"bytes"
	"testing"

	"github.com/cloudflare/gokeyless/protocol"
)

func TestTLS13ServerCertificateVerify(t *testing.T) {
	for _, n := range []int{32, 48} {
		hash := bytes.Repeat([]byte{0xAB}, n)
		msg := TLS13ServerCertificateVerify(hash)
		if want := 98 + n; len(msg) != want {
			t.Errorf("hash len %d: got payload len %d, want %d", n, len(msg), want)
		}
		if !protocol.ValidTLS13ServerCertificateVerify(msg) {
			t.Errorf("hash len %d: payload rejected by ValidTLS13ServerCertificateVerify", n)
		}
		if !bytes.HasSuffix(msg, hash) {
			t.Errorf("hash len %d: payload does not end with hash", n)
		}
	}

	// Hash lengths other than SHA-256/SHA-384 produce framing the keyserver rejects.
	for _, n := range []int{0, 31, 64} {
		if protocol.ValidTLS13ServerCertificateVerify(TLS13ServerCertificateVerify(make([]byte, n))) {
			t.Errorf("hash len %d: payload unexpectedly accepted", n)
		}
	}
}

func TestMLDSAParams(t *testing.T) {
	for _, p := range []MLDSASignParams{MLDSA44Params, MLDSA65Params, MLDSA87Params} {
		if !p.Opcode.IsMLDSASign() {
			t.Errorf("%v: not an ML-DSA opcode", p.Opcode)
		}
		if p.SignatureSize == 0 || p.SignatureSize != protocol.MLDSASignatureSize(p.Opcode) {
			t.Errorf("%v: SignatureSize %d mismatch", p.Opcode, p.SignatureSize)
		}
		if !protocol.ValidTLS13ServerCertificateVerify(TLS13ServerCertificateVerify(make([]byte, p.HashSize))) {
			t.Errorf("%v: HashSize %d yields invalid payload", p.Opcode, p.HashSize)
		}
	}
}
