package tests

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cloudflare/gokeyless/protocol"
	"github.com/cloudflare/gokeyless/server"
)

// End-to-end tests for the ML-DSA sign opcodes and the CertUsage tag. Every request
// goes over a real client→server TLS connection via Conn.DoOperation, so the
// operation is marshaled by the client, parsed by the server, and dispatched
// through the server's normal request handling.

// tls13ServerCertVerify returns a TLS 1.3 server CertificateVerify signing
// input (RFC 8446, Section 4.4.3) wrapping a transcript hash of hashLen bytes.
func tls13ServerCertVerify(hashLen int) []byte {
	msg := bytes.Repeat([]byte{0x20}, 64)
	msg = append(msg, "TLS 1.3, server CertificateVerify"...)
	msg = append(msg, 0x00)
	return append(msg, bytes.Repeat([]byte{0xab}, hashLen)...)
}

// fakeSignerCall records a single Sign invocation on a fakeMLDSASigner.
type fakeSignerCall struct {
	msg  []byte
	opts crypto.SignerOpts
}

// fakeMLDSASigner is a crypto.Signer standing in for an ML-DSA private key. It
// records every call and returns a deterministic signature of sigLen bytes.
type fakeMLDSASigner struct {
	sigLen int
	pubLen int // if non-zero, Public returns a key encoding of this length

	mtx   sync.Mutex
	calls []fakeSignerCall
}

// fakeMLDSAPublicKey is an encoded public key exposing Bytes.
type fakeMLDSAPublicKey []byte

func (p fakeMLDSAPublicKey) Bytes() []byte { return p }

func (f *fakeMLDSASigner) Public() crypto.PublicKey {
	if f.pubLen == 0 {
		return nil
	}
	return fakeMLDSAPublicKey(make([]byte, f.pubLen))
}

func (f *fakeMLDSASigner) Sign(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.calls = append(f.calls, fakeSignerCall{msg: append([]byte(nil), msg...), opts: opts})
	return bytes.Repeat([]byte{0x5a}, f.sigLen), nil
}

func (f *fakeMLDSASigner) Calls() []fakeSignerCall {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	return append([]fakeSignerCall(nil), f.calls...)
}

// fakeKeystore records a copy of every operation it is asked to resolve, by
// method, and returns signer (which may be nil to simulate "key not found").
type fakeKeystore struct {
	signer crypto.Signer

	mtx   sync.Mutex
	ops   []protocol.Operation // via Get
	cuOps []protocol.Operation // via GetByCertUsage
}

func (k *fakeKeystore) record(dst *[]protocol.Operation, op *protocol.Operation) (crypto.Signer, error) {
	k.mtx.Lock()
	defer k.mtx.Unlock()
	cp := *op
	if op.CertUsage != nil {
		cu := *op.CertUsage
		cp.CertUsage = &cu
	}
	*dst = append(*dst, cp)
	if k.signer == nil {
		// Return an untyped nil so the server sees key == nil.
		return nil, nil
	}
	return k.signer, nil
}

func (k *fakeKeystore) Get(_ context.Context, op *protocol.Operation) (crypto.Signer, error) {
	return k.record(&k.ops, op)
}

func (k *fakeKeystore) GetByCertUsage(_ context.Context, op *protocol.Operation) (crypto.Signer, error) {
	return k.record(&k.cuOps, op)
}

// Ops returns the operations resolved via Get.
func (k *fakeKeystore) Ops() []protocol.Operation {
	k.mtx.Lock()
	defer k.mtx.Unlock()
	return append([]protocol.Operation(nil), k.ops...)
}

// CertUsageOps returns the operations resolved via GetByCertUsage.
func (k *fakeKeystore) CertUsageOps() []protocol.Operation {
	k.mtx.Lock()
	defer k.mtx.Unlock()
	return append([]protocol.Operation(nil), k.cuOps...)
}

// getOnlyKeystore hides GetByCertUsage, like a keystore without certificate
// usage support.
type getOnlyKeystore struct{ k *fakeKeystore }

func (g getOnlyKeystore) Get(ctx context.Context, op *protocol.Operation) (crypto.Signer, error) {
	return g.k.Get(ctx, op)
}

// useKeystore swaps the server's keystore for keys and returns a function that
// restores the keystore SetupTest installed, so other suite tests (and later
// subtests sharing this server) are unaffected.
func (s *IntegrationTestSuite) useKeystore(keys server.Keystore) (restore func()) {
	orig := s.keys
	s.server.SetKeystore(keys)
	return func() { s.server.SetKeystore(orig) }
}

// doOp sends op over a fresh connection to the suite's server and returns the
// server's response.
func (s *IntegrationTestSuite) doOp(op protocol.Operation) *protocol.Operation {
	require := require.New(s.T())
	conn, err := s.remote.Dial(s.client)
	require.NoError(err)
	defer func() { _ = conn.Close() }()

	resp, err := conn.DoOperation(context.Background(), op)
	require.NoError(err)
	require.NotNil(resp)
	return resp
}

// requireOpError asserts resp is an OpError response carrying want.
func requireOpError(t require.TestingT, want protocol.Error, resp *protocol.Operation) {
	require.Equal(t, protocol.OpError, resp.Opcode, "expected error response, got %v", resp.Opcode)
	require.Equal(t, want, resp.ErrorVal(), "got %v", resp.GetError())
}

var mldsaOpcodes = []protocol.Op{
	protocol.OpMLDSA44Sign,
	protocol.OpMLDSA65Sign,
	protocol.OpMLDSA87Sign,
}

var testSKI = protocol.SKI{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
	0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}

func (s *IntegrationTestSuite) TestMLDSASignSuccess() {
	cu := &protocol.CertUsage{Usage: protocol.CertUsageServiceServer, Scope: "example"}

	for _, opcode := range mldsaOpcodes {
		for _, hashLen := range []int{32, 48} {
			for _, withCertUsage := range []bool{false, true} {
				name := fmt.Sprintf("%s/hash%d/cu=%t", opcode, hashLen, withCertUsage)
				s.Run(name, func() {
					require := require.New(s.T())

					signer := &fakeMLDSASigner{sigLen: protocol.MLDSASignatureSize(opcode)}
					keys := &fakeKeystore{signer: signer}
					defer s.useKeystore(keys)()

					payload := tls13ServerCertVerify(hashLen)
					op := protocol.Operation{Opcode: opcode, Payload: payload, SKI: testSKI, SNI: "example.com"}
					if withCertUsage {
						op.CertUsage = cu
					}

					resp := s.doOp(op)
					require.Equal(protocol.OpResponse, resp.Opcode, "unexpected error: %v", resp.GetError())
					require.Len(resp.Payload, protocol.MLDSASignatureSize(opcode))
					require.Equal(bytes.Repeat([]byte{0x5a}, protocol.MLDSASignatureSize(opcode)), resp.Payload)

					// The signer must see the raw message with no pre-hash.
					calls := signer.Calls()
					require.Len(calls, 1)
					require.Equal(payload, calls[0].msg)
					require.Equal(crypto.Hash(0), calls[0].opts)

					// The keystore must see the op as sent, including CertUsage,
					// via GetByCertUsage only when CertUsage is set.
					ops, other := keys.Ops(), keys.CertUsageOps()
					if withCertUsage {
						ops, other = other, ops
					}
					require.Empty(other)
					require.Len(ops, 1)
					require.Equal(opcode, ops[0].Opcode)
					require.Equal(testSKI, ops[0].SKI)
					require.Equal("example.com", ops[0].SNI)
					if withCertUsage {
						require.NotNil(ops[0].CertUsage)
						require.Equal(protocol.CertUsageServiceServer, ops[0].CertUsage.Usage)
						require.Equal("example", ops[0].CertUsage.Scope)
					} else {
						require.Nil(ops[0].CertUsage)
					}
				})
			}
		}
	}
}

func (s *IntegrationTestSuite) TestMLDSASignInvalidPayload() {
	valid := tls13ServerCertVerify(32)

	badPrefix := tls13ServerCertVerify(32)
	badPrefix[0] = 0x21

	badContext := tls13ServerCertVerify(48)
	copy(badContext[64:], "TLS 1.3, client CertificateVerify")

	badSeparator := tls13ServerCertVerify(32)
	badSeparator[97] = 0x01

	cases := []struct {
		name    string
		payload []byte
	}{
		{"len129", valid[:129]},
		{"len131", append(append([]byte(nil), valid...), 0xab)},
		{"empty", nil},
		{"wrong-pad", badPrefix},
		{"client-context", badContext},
		{"wrong-separator", badSeparator},
	}

	for _, opcode := range mldsaOpcodes {
		for _, tc := range cases {
			s.Run(fmt.Sprintf("%s/%s", opcode, tc.name), func() {
				signer := &fakeMLDSASigner{sigLen: protocol.MLDSASignatureSize(opcode)}
				keys := &fakeKeystore{signer: signer}
				defer s.useKeystore(keys)()

				resp := s.doOp(protocol.Operation{Opcode: opcode, Payload: tc.payload, SKI: testSKI})
				requireOpError(s.T(), protocol.ErrFormat, resp)
				// Framing is checked before the key lookup.
				require.Empty(s.T(), keys.Ops(), "keystore must not be consulted")
				require.Empty(s.T(), signer.Calls(), "signer must not be called")
			})
		}
	}
}

func (s *IntegrationTestSuite) TestMLDSASignWrongSignatureSize() {
	for _, opcode := range mldsaOpcodes {
		for _, sigLen := range []int{64 /* ed25519-like */, protocol.MLDSASignatureSize(opcode) - 1, protocol.MLDSASignatureSize(opcode) + 1} {
			s.Run(fmt.Sprintf("%s/sig%d", opcode, sigLen), func() {
				signer := &fakeMLDSASigner{sigLen: sigLen}
				defer s.useKeystore(&fakeKeystore{signer: signer})()

				resp := s.doOp(protocol.Operation{Opcode: opcode, Payload: tls13ServerCertVerify(32), SKI: testSKI})
				requireOpError(s.T(), protocol.ErrCrypto, resp)
				require.Len(s.T(), signer.Calls(), 1)
			})
		}
	}
}

// TestMLDSAKeyRejectedForOtherSignOps checks that an ML-DSA key is never used
// by a non-ML-DSA sign opcode, which would bypass the payload check.
func (s *IntegrationTestSuite) TestMLDSAKeyRejectedForOtherSignOps() {
	cu := &protocol.CertUsage{Usage: protocol.CertUsageServiceServer, Scope: "example"}
	digest := make([]byte, 32)
	for _, opcode := range []protocol.Op{protocol.OpEd25519Sign, protocol.OpECDSASignSHA256, protocol.OpRSASignSHA256, protocol.OpRSAPSSSignSHA256} {
		for _, withCertUsage := range []bool{false, true} {
			s.Run(fmt.Sprintf("%s/cu=%t", opcode, withCertUsage), func() {
				signer := &fakeMLDSASigner{sigLen: 64, pubLen: 1952}
				defer s.useKeystore(&fakeKeystore{signer: signer})()

				op := protocol.Operation{Opcode: opcode, Payload: digest, SKI: testSKI}
				if withCertUsage {
					op.CertUsage = cu
				}
				requireOpError(s.T(), protocol.ErrCrypto, s.doOp(op))
				require.Empty(s.T(), signer.Calls())
			})
		}
	}
}

func (s *IntegrationTestSuite) TestMLDSASignKeyNotFound() {
	for _, opcode := range mldsaOpcodes {
		s.Run(opcode.String(), func() {
			keys := &fakeKeystore{signer: nil}
			defer s.useKeystore(keys)()

			resp := s.doOp(protocol.Operation{Opcode: opcode, Payload: tls13ServerCertVerify(48), SKI: testSKI})
			requireOpError(s.T(), protocol.ErrKeyNotFound, resp)
			require.Len(s.T(), keys.Ops(), 1)
		})
	}
}

func (s *IntegrationTestSuite) TestCertUsageInvalidCombinations() {
	cu := &protocol.CertUsage{Usage: protocol.CertUsageServiceServer, Scope: "example"}
	digest := hashMsg(crypto.SHA256)

	cases := []struct {
		name string
		op   protocol.Operation
	}{
		{"mldsa/extra", protocol.Operation{Opcode: protocol.OpMLDSA65Sign, Payload: tls13ServerCertVerify(32), SKI: testSKI, CertUsage: cu, Extra: []byte("extra")}},
		{"mldsa/certid", protocol.Operation{Opcode: protocol.OpMLDSA65Sign, Payload: tls13ServerCertVerify(32), SKI: testSKI, CertUsage: cu, CertID: "cert-id"}},
		{"ecdsa/extra", protocol.Operation{Opcode: protocol.OpECDSASignSHA256, Payload: digest, SKI: testSKI, CertUsage: cu, Extra: []byte("extra")}},
		{"ecdsa/certid", protocol.Operation{Opcode: protocol.OpECDSASignSHA256, Payload: digest, SKI: testSKI, CertUsage: cu, CertID: "cert-id"}},
		{"mldsa/unknown-usage", protocol.Operation{Opcode: protocol.OpMLDSA44Sign, Payload: tls13ServerCertVerify(32), SKI: testSKI, CertUsage: &protocol.CertUsage{Usage: 0x02, Scope: "example"}}},
		{"mldsa/empty-scope", protocol.Operation{Opcode: protocol.OpMLDSA44Sign, Payload: tls13ServerCertVerify(32), SKI: testSKI, CertUsage: &protocol.CertUsage{Usage: protocol.CertUsageServiceServer}}},
		{"mldsa/bad-scope", protocol.Operation{Opcode: protocol.OpMLDSA44Sign, Payload: tls13ServerCertVerify(32), SKI: testSKI, CertUsage: &protocol.CertUsage{Usage: protocol.CertUsageServiceServer, Scope: "Example!"}}},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			signer := &fakeMLDSASigner{sigLen: protocol.MLDSASignatureSize(protocol.OpMLDSA65Sign)}
			keys := &fakeKeystore{signer: signer}
			defer s.useKeystore(keys)()

			resp := s.doOp(tc.op)
			requireOpError(s.T(), protocol.ErrFormat, resp)
			require.Empty(s.T(), keys.Ops(), "keystore must not be consulted")
			require.Empty(s.T(), keys.CertUsageOps(), "keystore must not be consulted")
		})
	}
}

// TestCertUsageKeystoreWithoutSupport checks that a keystore implementing only
// Get is never consulted for a valid CertUsage request, which gets ErrKeyNotFound.
func (s *IntegrationTestSuite) TestCertUsageKeystoreWithoutSupport() {
	cu := &protocol.CertUsage{Usage: protocol.CertUsageServiceServer, Scope: "example"}
	ops := []protocol.Operation{
		{Opcode: protocol.OpMLDSA65Sign, Payload: tls13ServerCertVerify(32), SKI: testSKI, CertUsage: cu},
		{Opcode: protocol.OpECDSASignSHA256, Payload: hashMsg(crypto.SHA256), SKI: testSKI, CertUsage: cu},
	}
	for _, op := range ops {
		s.Run(op.Opcode.String(), func() {
			signer := &fakeMLDSASigner{sigLen: protocol.MLDSASignatureSize(protocol.OpMLDSA65Sign)}
			keys := &fakeKeystore{signer: signer}
			defer s.useKeystore(getOnlyKeystore{keys})()

			requireOpError(s.T(), protocol.ErrKeyNotFound, s.doOp(op))
			require.Empty(s.T(), keys.Ops(), "Get must not be called")
			require.Empty(s.T(), signer.Calls())
		})
	}
}

// TestCertUsageDefaultKeystoreNoFallback uses the suite's real keystore: an ECDSA
// sign for a loaded key's SKI succeeds without CertUsage, but the same request with
// a valid CertUsage tag must not fall back to SKI lookup and returns ErrKeyNotFound.
func (s *IntegrationTestSuite) TestCertUsageDefaultKeystoreNoFallback() {
	require := require.New(s.T())

	ski, err := protocol.GetSKI(s.ecdsaKey.Public())
	require.NoError(err)
	digest := hashMsg(crypto.SHA256)

	op := protocol.Operation{Opcode: protocol.OpECDSASignSHA256, Payload: digest, SKI: ski}
	resp := s.doOp(op)
	require.Equal(protocol.OpResponse, resp.Opcode, "unexpected error: %v", resp.GetError())
	require.NoError(checkSignature(s.ecdsaKey.Public(), crypto.SHA256, resp.Payload))

	op.CertUsage = &protocol.CertUsage{Usage: protocol.CertUsageServiceServer, Scope: "example"}
	resp = s.doOp(op)
	requireOpError(s.T(), protocol.ErrKeyNotFound, resp)

	// ML-DSA with CertUsage against the default keystore: also not found.
	resp = s.doOp(protocol.Operation{Opcode: protocol.OpMLDSA65Sign, Payload: tls13ServerCertVerify(32), SKI: ski, CertUsage: op.CertUsage})
	requireOpError(s.T(), protocol.ErrKeyNotFound, resp)
}

// TestMLDSASignLimitedConnection starts a second server whose connections are
// all limited and checks that ML-DSA opcodes are rejected with ErrBadOpcode
// without consulting the keystore.
func (s *IntegrationTestSuite) TestMLDSASignLimitedConnection() {
	require := require.New(s.T())

	config := server.DefaultServeConfig().
		WithSignTimeout(s.timeout).
		WithSignRetryCount(s.retryCount).
		WithIsLimited(func(tls.ConnectionState) (bool, error) { return true, nil })
	limitedServer, err := server.NewServerFromFile(config, serverCert, serverKey, keylessCA)
	require.NoError(err)
	limitedServer.TLSConfig().Time = fixedCurrentTime
	signer := &fakeMLDSASigner{sigLen: protocol.MLDSASignatureSize(protocol.OpMLDSA44Sign)}
	keys := &fakeKeystore{signer: signer}
	limitedServer.SetKeystore(keys)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(err)
	listening := make(chan struct{})
	go func() {
		close(listening)
		_ = limitedServer.Serve(l) // returns an Accept error once Close is called
	}()
	<-listening
	defer func() { require.NoError(shutdownServer(limitedServer, 2*time.Second)) }()

	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	remote, err := s.client.LookupServerWithName("localhost", "127.0.0.1", port)
	require.NoError(err)

	for _, opcode := range mldsaOpcodes {
		s.Run(opcode.String(), func() {
			conn, err := remote.Dial(s.client)
			require.NoError(err)
			defer func() { _ = conn.Close() }()

			resp, err := conn.DoOperation(context.Background(), protocol.Operation{
				Opcode:    opcode,
				Payload:   tls13ServerCertVerify(32),
				SKI:       testSKI,
				CertUsage: &protocol.CertUsage{Usage: protocol.CertUsageServiceServer, Scope: "example"},
			})
			require.NoError(err)
			requireOpError(s.T(), protocol.ErrBadOpcode, resp)
		})
	}
	require.Empty(keys.Ops(), "limited connections must not consult the keystore")
	require.Empty(keys.CertUsageOps(), "limited connections must not consult the keystore")

	// Sanity: the limited connection is otherwise functional.
	conn, err := remote.Dial(s.client)
	require.NoError(err)
	defer func() { _ = conn.Close() }()
	require.NoError(conn.Ping(context.Background(), []byte("hi")))
}
