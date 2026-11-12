package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/gokeyless/protocol"
	"github.com/stretchr/testify/require"
)

// stubSigner is a crypto.Signer returning a fixed signature/error and
// recording the arguments it was called with.
type stubSigner struct {
	sig     []byte
	err     error
	pub     crypto.PublicKey // nil unless set
	called  bool
	calls   int
	gotMsg  []byte
	gotOpts crypto.SignerOpts
}

func (s *stubSigner) Public() crypto.PublicKey { return s.pub }

func (s *stubSigner) Sign(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.called = true
	s.calls++
	s.gotMsg = msg
	s.gotOpts = opts
	return s.sig, s.err
}

// stubKeystore returns a fixed key/error and counts Get calls.
type stubKeystore struct {
	key   crypto.Signer
	err   error
	calls int
}

func (k *stubKeystore) Get(context.Context, *protocol.Operation) (crypto.Signer, error) {
	k.calls++
	return k.key, k.err
}

// stubCertUsageKeystore also implements CertUsageKeystore, counting
// GetByCertUsage calls separately from Get calls.
type stubCertUsageKeystore struct {
	stubKeystore
	cuCalls int
}

func (k *stubCertUsageKeystore) GetByCertUsage(context.Context, *protocol.Operation) (crypto.Signer, error) {
	k.cuCalls++
	return k.key, k.err
}

func validCertVerify(hashLen int) []byte {
	msg := bytes.Repeat([]byte{0x20}, 64)
	msg = append(msg, "TLS 1.3, server CertificateVerify"...)
	msg = append(msg, 0x00)
	return append(msg, bytes.Repeat([]byte{0xAB}, hashLen)...)
}

func mldsaPacket(op protocol.Op, payload []byte) *protocol.Packet {
	return &protocol.Packet{
		Header:    protocol.Header{MajorVers: 0x01, ID: 7},
		Operation: protocol.Operation{Opcode: op, Payload: payload},
	}
}

func requireErrResp(t *testing.T, resp response, want protocol.Error) {
	t.Helper()
	require.Equal(t, protocol.OpError, resp.op.Opcode)
	require.Equal(t, []byte{byte(want)}, resp.op.Payload)
}

func TestUnlimitedDoMLDSASign(t *testing.T) {
	ops := []protocol.Op{protocol.OpMLDSA44Sign, protocol.OpMLDSA65Sign, protocol.OpMLDSA87Sign}

	for _, op := range ops {
		t.Run(op.String(), func(t *testing.T) {
			size := protocol.MLDSASignatureSize(op)

			t.Run("success", func(t *testing.T) {
				for _, hashLen := range []int{32, 48} {
					sig := bytes.Repeat([]byte{0x5A}, size)
					signer := &stubSigner{sig: sig}
					ks := &stubKeystore{key: signer}
					s := &Server{config: DefaultServeConfig(), keys: ks}
					payload := validCertVerify(hashLen)

					resp := s.unlimitedDo(mldsaPacket(op, payload), "test")
					require.Equal(t, uint32(7), resp.id)
					require.Equal(t, protocol.OpResponse, resp.op.Opcode)
					require.Equal(t, sig, resp.op.Payload)
					require.True(t, signer.called)
					require.Equal(t, payload, signer.gotMsg)
					require.Equal(t, crypto.Hash(0), signer.gotOpts)
				}
			})

			t.Run("invalid payload rejected before key lookup", func(t *testing.T) {
				bad := validCertVerify(32)
				bad[0] = 0x21
				for _, payload := range [][]byte{nil, []byte("arbitrary"), validCertVerify(31), bad} {
					ks := &stubKeystore{key: &stubSigner{sig: make([]byte, size)}}
					s := &Server{config: DefaultServeConfig(), keys: ks}
					requireErrResp(t, s.unlimitedDo(mldsaPacket(op, payload), "test"), protocol.ErrFormat)
					require.Zero(t, ks.calls)
				}
			})

			t.Run("keystore error", func(t *testing.T) {
				s := &Server{config: DefaultServeConfig(), keys: &stubKeystore{err: errors.New("boom")}}
				requireErrResp(t, s.unlimitedDo(mldsaPacket(op, validCertVerify(32)), "test"), protocol.ErrInternal)
			})

			t.Run("key not found", func(t *testing.T) {
				s := &Server{config: DefaultServeConfig(), keys: &stubKeystore{}}
				requireErrResp(t, s.unlimitedDo(mldsaPacket(op, validCertVerify(32)), "test"), protocol.ErrKeyNotFound)
			})

			t.Run("remote configuration error", func(t *testing.T) {
				signer := &stubSigner{err: RemoteConfigurationErr{Err: errors.New("remote")}}
				s := &Server{config: DefaultServeConfig(), keys: &stubKeystore{key: signer}}
				requireErrResp(t, s.unlimitedDo(mldsaPacket(op, validCertVerify(32)), "test"), protocol.ErrRemoteConfiguration)
			})

			t.Run("sign error", func(t *testing.T) {
				signer := &stubSigner{err: errors.New("sign failed")}
				s := &Server{config: DefaultServeConfig(), keys: &stubKeystore{key: signer}}
				requireErrResp(t, s.unlimitedDo(mldsaPacket(op, validCertVerify(32)), "test"), protocol.ErrCrypto)
			})

			t.Run("wrong signature length", func(t *testing.T) {
				for _, n := range []int{0, 64, size - 1, size + 1} {
					signer := &stubSigner{sig: make([]byte, n)}
					s := &Server{config: DefaultServeConfig(), keys: &stubKeystore{key: signer}}
					requireErrResp(t, s.unlimitedDo(mldsaPacket(op, validCertVerify(32)), "test"), protocol.ErrCrypto)
				}
			})
		})
	}
}

func TestLimitedDoMLDSASignBadOpcode(t *testing.T) {
	for _, op := range []protocol.Op{protocol.OpMLDSA44Sign, protocol.OpMLDSA65Sign, protocol.OpMLDSA87Sign} {
		ks := &stubKeystore{key: &stubSigner{sig: make([]byte, protocol.MLDSASignatureSize(op))}}
		s := &Server{config: DefaultServeConfig(), keys: ks}
		requireErrResp(t, s.limitedDo(mldsaPacket(op, validCertVerify(32)), "test"), protocol.ErrBadOpcode)
		require.Zero(t, ks.calls)
	}
}

// sizedPub is a public key exposing Bytes, like an ML-DSA public key.
type sizedPub struct{ n int }

func (p sizedPub) Bytes() []byte { return make([]byte, p.n) }

// marshalerPub is a public key exposing only encoding.BinaryMarshaler.
type marshalerPub struct{ n int }

func (p marshalerPub) MarshalBinary() ([]byte, error) { return make([]byte, p.n), nil }

func TestUnlimitedDoMLDSAKeyMismatch(t *testing.T) {
	for _, op := range []protocol.Op{protocol.OpMLDSA44Sign, protocol.OpMLDSA65Sign, protocol.OpMLDSA87Sign} {
		t.Run(op.String(), func(t *testing.T) {
			size := mldsaPublicKeySize(op)
			rejected := map[string]crypto.PublicKey{
				"rsa":             &rsa.PublicKey{},
				"ecdsa":           &ecdsa.PublicKey{},
				"ed25519":         ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)),
				"short bytes":     sizedPub{size - 1},
				"long bytes":      sizedPub{size + 1},
				"short marshaler": marshalerPub{size - 1},
			}
			for name, pub := range rejected {
				signer := &stubSigner{sig: make([]byte, protocol.MLDSASignatureSize(op)), pub: pub}
				s := &Server{config: DefaultServeConfig(), keys: &stubKeystore{key: signer}}
				requireErrResp(t, s.unlimitedDo(mldsaPacket(op, validCertVerify(32)), "test"), protocol.ErrCrypto)
				require.Zero(t, signer.calls, name)
			}

			accepted := map[string]crypto.PublicKey{
				"bytes":     sizedPub{size},
				"marshaler": marshalerPub{size},
				"unknown":   struct{}{},
				"nil":       nil,
			}
			for name, pub := range accepted {
				signer := &stubSigner{sig: make([]byte, protocol.MLDSASignatureSize(op)), pub: pub}
				s := &Server{config: DefaultServeConfig(), keys: &stubKeystore{key: signer}}
				resp := s.unlimitedDo(mldsaPacket(op, validCertVerify(32)), "test")
				require.Equal(t, protocol.OpResponse, resp.op.Opcode, name)
				require.Equal(t, 1, signer.calls, name)
			}
		})
	}
}

// nonMLDSASignOps lists every non-ML-DSA sign opcode.
func nonMLDSASignOps() []protocol.Op {
	var ops []protocol.Op
	for _, op := range allKeyOps() {
		if op != protocol.OpRSADecrypt && protocol.MLDSASignatureSize(op) == 0 {
			ops = append(ops, op)
		}
	}
	return ops
}

func TestUnlimitedDoMLDSAKeyRejectedForOtherSignOps(t *testing.T) {
	for _, op := range nonMLDSASignOps() {
		for _, n := range []int{1312, 1952, 2592} {
			for _, pub := range []crypto.PublicKey{sizedPub{n}, marshalerPub{n}} {
				for _, withCertUsage := range []bool{false, true} {
					signer := &stubSigner{sig: []byte{0x01}, pub: pub}
					ks := &stubCertUsageKeystore{stubKeystore: stubKeystore{key: signer}}
					var cu *protocol.CertUsage
					if withCertUsage {
						cu = validCertUsage()
					}
					s := &Server{config: DefaultServeConfig(), keys: ks}
					requireErrResp(t, s.unlimitedDo(certUsagePacket(op, cu), "test"), protocol.ErrCrypto)
					require.Zero(t, signer.calls, "op %s size %d certUsage %v", op, n, withCertUsage)
					require.Equal(t, 1, ks.calls+ks.cuCalls)
				}
			}
		}
	}
}

func TestUnlimitedDoNonMLDSAKeyStillSigns(t *testing.T) {
	for _, op := range nonMLDSASignOps() {
		for name, pub := range map[string]crypto.PublicKey{"nil": nil, "unknown": struct{}{}, "other size": sizedPub{32}} {
			signer := &stubSigner{sig: []byte{0x01}, pub: pub}
			s := &Server{config: DefaultServeConfig(), keys: &stubKeystore{key: signer}}
			resp := s.unlimitedDo(certUsagePacket(op, nil), "test")
			if op == protocol.OpEd25519Sign {
				// Ed25519 sign fails closed for non-Ed25519 public keys.
				requireErrResp(t, resp, protocol.ErrCrypto)
				require.Zero(t, signer.calls, "op %s %s", op, name)
				continue
			}
			require.Equal(t, protocol.OpResponse, resp.op.Opcode, "op %s %s", op, name)
			require.Equal(t, 1, signer.calls, "op %s %s", op, name)
		}
	}
}

func TestUnlimitedDoEd25519SignRequiresEd25519Key(t *testing.T) {
	rejected := map[string]crypto.PublicKey{
		"rsa":           &rsa.PublicKey{},
		"ecdsa":         &ecdsa.PublicKey{},
		"short ed25519": ed25519.PublicKey(make([]byte, ed25519.PublicKeySize-1)),
		"mldsa-sized":   sizedPub{1952},
		"marshaler":     marshalerPub{32},
	}
	for name, pub := range rejected {
		signer := &stubSigner{sig: make([]byte, ed25519.SignatureSize), pub: pub}
		s := &Server{config: DefaultServeConfig(), keys: &stubKeystore{key: signer}}
		requireErrResp(t, s.unlimitedDo(certUsagePacket(protocol.OpEd25519Sign, nil), "test"), protocol.ErrCrypto)
		require.Zero(t, signer.calls, name)
	}
}

func TestUnlimitedDoEd25519SignOpaqueSigner(t *testing.T) {
	for _, cu := range []*protocol.CertUsage{nil, validCertUsage()} {
		sig := bytes.Repeat([]byte{0x5A}, ed25519.SignatureSize)
		signer := &stubSigner{sig: sig, pub: ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))}
		s := &Server{config: DefaultServeConfig(), keys: &stubCertUsageKeystore{stubKeystore: stubKeystore{key: signer}}}
		pkt := certUsagePacket(protocol.OpEd25519Sign, cu)
		resp := s.unlimitedDo(pkt, "test")
		require.Equal(t, protocol.OpResponse, resp.op.Opcode)
		require.Equal(t, sig, resp.op.Payload)
		require.Equal(t, 1, signer.calls)
		require.Equal(t, pkt.Payload, signer.gotMsg)
		require.Equal(t, crypto.Hash(0), signer.gotOpts)
	}
}

func TestUnlimitedDoMLDSASizedSignatureRejectedForOtherSignOps(t *testing.T) {
	for _, op := range nonMLDSASignOps() {
		if op == protocol.OpEd25519Sign {
			continue // rejected before signing; see TestUnlimitedDoEd25519SignRequiresEd25519Key
		}
		for _, n := range []int{2420, 3309, 4627} {
			signer := &stubSigner{sig: make([]byte, n)} // nil public key
			s := &Server{config: DefaultServeConfig(), keys: &stubKeystore{key: signer}}
			requireErrResp(t, s.unlimitedDo(certUsagePacket(op, nil), "test"), protocol.ErrCrypto)
			require.Equal(t, 1, signer.calls, "op %s sig %d", op, n)
		}
	}
	// Neighbouring lengths are unaffected.
	for _, n := range []int{2419, 3310} {
		signer := &stubSigner{sig: make([]byte, n)}
		s := &Server{config: DefaultServeConfig(), keys: &stubKeystore{key: signer}}
		resp := s.unlimitedDo(certUsagePacket(protocol.OpECDSASignSHA256, nil), "test")
		require.Equal(t, protocol.OpResponse, resp.op.Opcode, "sig %d", n)
	}
}

func TestIsMLDSASignatureLen(t *testing.T) {
	for _, op := range []protocol.Op{protocol.OpMLDSA44Sign, protocol.OpMLDSA65Sign, protocol.OpMLDSA87Sign} {
		n := protocol.MLDSASignatureSize(op)
		require.True(t, isMLDSASignatureLen(n))
		require.False(t, isMLDSASignatureLen(n+1))
	}
	require.False(t, isMLDSASignatureLen(0))
	require.False(t, isMLDSASignatureLen(ed25519.SignatureSize))
}

func TestUnlimitedDoEd25519SignRealKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	for _, cu := range []*protocol.CertUsage{nil, validCertUsage()} {
		s := &Server{config: DefaultServeConfig(), keys: &stubCertUsageKeystore{stubKeystore: stubKeystore{key: priv}}}
		pkt := certUsagePacket(protocol.OpEd25519Sign, cu)
		resp := s.unlimitedDo(pkt, "test")
		require.Equal(t, protocol.OpResponse, resp.op.Opcode)
		require.True(t, ed25519.Verify(pub, pkt.Payload, resp.op.Payload))
	}
}

func TestIsMLDSAPublicKey(t *testing.T) {
	for _, n := range []int{1312, 1952, 2592} {
		require.True(t, isMLDSAPublicKey(sizedPub{n}))
		require.True(t, isMLDSAPublicKey(marshalerPub{n}))
		require.False(t, isMLDSAPublicKey(sizedPub{n + 1}))
	}
	for _, pub := range []crypto.PublicKey{nil, struct{}{}, &rsa.PublicKey{}, &ecdsa.PublicKey{}, ed25519.PublicKey(make([]byte, 1312))} {
		require.False(t, isMLDSAPublicKey(pub))
	}
}

// slowSigner blocks in Sign until release is closed.
type slowSigner struct {
	release chan struct{}
	calls   atomic.Int32
}

func (s *slowSigner) Public() crypto.PublicKey { return nil }

func (s *slowSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	s.calls.Add(1)
	<-s.release
	return nil, errors.New("released")
}

func TestUnlimitedDoMLDSASignTimeoutAndRetry(t *testing.T) {
	const timeout = 20 * time.Millisecond
	signer := &slowSigner{release: make(chan struct{})}
	t.Cleanup(func() { close(signer.release) })

	s, err := NewServer(DefaultServeConfig().WithSignTimeout(timeout).WithSignRetryCount(2), tls.Certificate{}, nil)
	require.NoError(t, err)
	s.SetKeystore(&stubKeystore{key: signer})

	start := time.Now()
	resp := s.unlimitedDo(mldsaPacket(protocol.OpMLDSA65Sign, validCertVerify(32)), "test")
	requireErrResp(t, resp, protocol.ErrCrypto)
	require.Less(t, time.Since(start), 2*time.Second)
	// One attempt plus two retries, each abandoned after the timeout.
	require.Eventually(t, func() bool { return signer.calls.Load() == 3 }, time.Second, 5*time.Millisecond)
}
