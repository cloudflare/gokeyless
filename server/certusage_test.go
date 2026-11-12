package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/cloudflare/gokeyless/protocol"
	"github.com/stretchr/testify/require"
)

func validCertUsage() *protocol.CertUsage {
	return &protocol.CertUsage{Usage: protocol.CertUsageServiceServer, Scope: "svc-a_1"}
}

// certUsagePacket builds a packet for op with a payload that passes any opcode
// specific pre-checks (the TLS 1.3 CertificateVerify framing for ML-DSA).
func certUsagePacket(op protocol.Op, cu *protocol.CertUsage) *protocol.Packet {
	pkt := mldsaPacket(op, validCertVerify(32))
	pkt.Operation.SKI = protocol.SKI{0x01}
	pkt.Operation.CertUsage = cu
	return pkt
}

// allKeyOps lists every opcode that unlimitedDo serves via the keystore.
func allKeyOps() []protocol.Op {
	return []protocol.Op{
		protocol.OpRSADecrypt,
		protocol.OpEd25519Sign,
		protocol.OpMLDSA44Sign, protocol.OpMLDSA65Sign, protocol.OpMLDSA87Sign,
		protocol.OpRSASignMD5SHA1, protocol.OpECDSASignMD5SHA1,
		protocol.OpRSASignSHA1, protocol.OpECDSASignSHA1,
		protocol.OpRSASignSHA224, protocol.OpECDSASignSHA224,
		protocol.OpRSASignSHA256, protocol.OpRSAPSSSignSHA256, protocol.OpECDSASignSHA256,
		protocol.OpRSASignSHA384, protocol.OpRSAPSSSignSHA384, protocol.OpECDSASignSHA384,
		protocol.OpRSASignSHA512, protocol.OpRSAPSSSignSHA512, protocol.OpECDSASignSHA512,
	}
}

func newCertUsageStub(op protocol.Op) *stubCertUsageKeystore {
	return &stubCertUsageKeystore{stubKeystore: stubKeystore{key: &stubSigner{sig: make([]byte, protocol.MLDSASignatureSize(op))}}}
}

func TestUnlimitedDoCertUsageInvalidRejectedBeforeKeyLookup(t *testing.T) {
	cases := map[string]func(*protocol.Operation){
		"with extra":   func(o *protocol.Operation) { o.Extra = []byte{0x00} },
		"with cert id": func(o *protocol.Operation) { o.CertID = "abc" },
		"bad usage":    func(o *protocol.Operation) { o.CertUsage.Usage = 0x02 },
		"zero usage":   func(o *protocol.Operation) { o.CertUsage.Usage = 0x00 },
		"empty scope":  func(o *protocol.Operation) { o.CertUsage.Scope = "" },
		"uppercase":    func(o *protocol.Operation) { o.CertUsage.Scope = "Svc" },
		"too long": func(o *protocol.Operation) {
			o.CertUsage.Scope = string(bytes.Repeat([]byte{'a'}, protocol.MaxCertUsageScopeLen+1))
		},
	}
	ops := allKeyOps()
	require.NotEmpty(t, ops)
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			for _, op := range ops {
				ks := newCertUsageStub(op)
				s := &Server{config: DefaultServeConfig(), keys: ks}
				pkt := certUsagePacket(op, validCertUsage())
				mutate(&pkt.Operation)
				requireErrResp(t, s.unlimitedDo(pkt, "test"), protocol.ErrFormat)
				require.Zero(t, ks.calls+ks.cuCalls, "op %s reached keystore", op)
			}
		})
	}
}

// TestUnlimitedDoCertUsageNoKeyOpBypassesValidation guards against a key opcode
// reaching the keystore with an invalid CertUsage item, or bypassing
// CertUsageKeystore with a valid one.
func TestUnlimitedDoCertUsageNoKeyOpBypassesValidation(t *testing.T) {
	var reached []protocol.Op
	for i := 0; i < 256; i++ {
		op := protocol.Op(i)
		if op == protocol.OpRPC { // needs a dispatcher; never uses the keystore
			continue
		}
		ks := newCertUsageStub(op)
		s := &Server{config: DefaultServeConfig(), keys: ks}
		pkt := certUsagePacket(op, validCertUsage())
		pkt.Operation.Extra = []byte{0x00}
		s.unlimitedDo(pkt, "test")
		require.Zero(t, ks.calls+ks.cuCalls, "op %s reached keystore with invalid CertUsage", op)

		ks = newCertUsageStub(op)
		s = &Server{config: DefaultServeConfig(), keys: ks}
		s.unlimitedDo(certUsagePacket(op, validCertUsage()), "test")
		require.Zero(t, ks.calls, "op %s called Get with CertUsage", op)
		if ks.cuCalls > 0 {
			reached = append(reached, op)
		}
	}
	require.ElementsMatch(t, allKeyOps(), reached)
}

func TestUnlimitedDoCertUsageValidPassesToKeystore(t *testing.T) {
	for _, op := range allKeyOps() {
		ks := newCertUsageStub(op)
		s := &Server{config: DefaultServeConfig(), keys: ks}
		s.unlimitedDo(certUsagePacket(op, validCertUsage()), "test")
		require.Equal(t, 1, ks.cuCalls, "op %s", op)
		require.Zero(t, ks.calls, "op %s", op)
	}

	for _, op := range []protocol.Op{protocol.OpMLDSA65Sign, protocol.OpECDSASignSHA256} {
		t.Run(op.String(), func(t *testing.T) {
			size := protocol.MLDSASignatureSize(op)
			if size == 0 {
				size = 72
			}
			sig := bytes.Repeat([]byte{0x5A}, size)
			ks := &stubCertUsageKeystore{stubKeystore: stubKeystore{key: &stubSigner{sig: sig}}}
			s := &Server{config: DefaultServeConfig(), keys: ks}
			resp := s.unlimitedDo(certUsagePacket(op, validCertUsage()), "test")
			require.Equal(t, protocol.OpResponse, resp.op.Opcode)
			require.Equal(t, sig, resp.op.Payload)
			require.Equal(t, 1, ks.cuCalls)
			require.Zero(t, ks.calls)
		})
	}
}

func TestUnlimitedDoCertUsageWithoutCertUsageKeystore(t *testing.T) {
	for _, op := range allKeyOps() {
		ks := &stubKeystore{key: &stubSigner{sig: make([]byte, protocol.MLDSASignatureSize(op))}}
		s := &Server{config: DefaultServeConfig(), keys: ks}
		requireErrResp(t, s.unlimitedDo(certUsagePacket(op, validCertUsage()), "test"), protocol.ErrKeyNotFound)
		require.Zero(t, ks.calls, "op %s called Get with CertUsage", op)
	}
}

func TestUnlimitedDoCertUsageKeystoreErrors(t *testing.T) {
	ks := &stubCertUsageKeystore{stubKeystore: stubKeystore{err: errors.New("boom")}}
	s := &Server{config: DefaultServeConfig(), keys: ks}
	requireErrResp(t, s.unlimitedDo(certUsagePacket(protocol.OpECDSASignSHA256, validCertUsage()), "test"), protocol.ErrInternal)

	ks = &stubCertUsageKeystore{}
	s = &Server{config: DefaultServeConfig(), keys: ks}
	requireErrResp(t, s.unlimitedDo(certUsagePacket(protocol.OpECDSASignSHA256, validCertUsage()), "test"), protocol.ErrKeyNotFound)
	require.Equal(t, 1, ks.cuCalls)
	require.Zero(t, ks.calls)
}

func TestUnlimitedDoNoCertUsageUnchanged(t *testing.T) {
	sig := []byte{0x01, 0x02}
	ks := &stubKeystore{key: &stubSigner{sig: sig}}
	s := &Server{config: DefaultServeConfig(), keys: ks}
	pkt := certUsagePacket(protocol.OpECDSASignSHA256, nil)
	// Extra/CertID remain allowed without CertUsage.
	pkt.Operation.Extra = []byte{0x00}
	pkt.Operation.CertID = "abc"
	resp := s.unlimitedDo(pkt, "test")
	require.Equal(t, protocol.OpResponse, resp.op.Opcode)
	require.Equal(t, sig, resp.op.Payload)
	require.Equal(t, 1, ks.calls)
}

func TestUnlimitedDoCertUsageIgnoredForPing(t *testing.T) {
	s := &Server{config: DefaultServeConfig(), keys: &stubKeystore{}}
	pkt := certUsagePacket(protocol.OpPing, validCertUsage())
	pkt.Operation.Payload = []byte("hi")
	pkt.Operation.Extra = []byte{0x00} // invalid CertUsage combination
	resp := s.unlimitedDo(pkt, "test")
	require.Equal(t, protocol.OpPong, resp.op.Opcode)
	require.Equal(t, []byte("hi"), resp.op.Payload)
}

func TestDefaultKeystoreCertUsageNeverFallsBackToSKI(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ski, err := protocol.GetSKI(priv.Public())
	require.NoError(t, err)

	keys := NewDefaultKeystore()
	require.NoError(t, keys.Add(nil, priv))
	_, ok := Keystore(keys).(CertUsageKeystore)
	require.False(t, ok, "DefaultKeystore must not implement CertUsageKeystore")

	// Sanity check: the SKI resolves without CertUsage.
	got, err := keys.Get(t.Context(), &protocol.Operation{SKI: ski})
	require.NoError(t, err)
	require.NotNil(t, got)

	got, err = keys.Get(t.Context(), &protocol.Operation{SKI: ski, CertUsage: validCertUsage()})
	require.NoError(t, err)
	require.Nil(t, got)

	s := &Server{config: DefaultServeConfig(), keys: keys}
	pkt := certUsagePacket(protocol.OpECDSASignSHA256, validCertUsage())
	pkt.Operation.SKI = ski
	pkt.Operation.Payload = make([]byte, 32)
	requireErrResp(t, s.unlimitedDo(pkt, "test"), protocol.ErrKeyNotFound)

	// Same request without CertUsage succeeds via SKI.
	pkt = certUsagePacket(protocol.OpECDSASignSHA256, nil)
	pkt.Operation.SKI = ski
	pkt.Operation.Payload = make([]byte, 32)
	require.Equal(t, protocol.OpResponse, s.unlimitedDo(pkt, "test").op.Opcode)
}
