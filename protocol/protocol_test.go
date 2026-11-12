package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMarshalBinary(t *testing.T) {
	require := require.New(t)

	// we want to push the payload over the paddedLength of 1024
	// to ensure that the size is calculated correctly.
	extra := make([]byte, 100)
	payload := make([]byte, 1000)
	reqCtx := make([]byte, 100)
	rand.Read(extra)
	rand.Read(payload)
	rand.Read(reqCtx)
	op := Operation{
		Opcode:           OpECDSASignSHA256,
		Payload:          payload,
		Extra:            extra,
		Digest:           sha256.Sum256([]byte("Digest")),
		SKI:              sha1.Sum([]byte("SKI")),
		ClientIP:         net.ParseIP("1.1.1.1").To4(),
		ServerIP:         net.ParseIP("2.2.2.2").To4(),
		SNI:              "SNI",
		CertID:           "SNI",
		CustomFuncName:   "CustomFuncName",
		JaegerSpan:       []byte("615f730ad5fe896f:615f730ad5fe896f:1"),
		ReqContext:       reqCtx,
		ComplianceRegion: ComplianceRegionFedRAMPHigh,
	}
	pkt := NewPacket(42, op)
	b, err := pkt.MarshalBinary()
	require.NoError(err)

	var pkt2 Packet
	size, err := pkt2.ReadFrom(bytes.NewReader(b))
	require.NoError(err)
	require.Equal(pkt.ID, pkt2.ID)
	require.Equal(op, pkt2.Operation)

	// now do the same test with a 0 value for compliance region
	globalOp := Operation{
		Opcode:         OpECDSASignSHA256,
		Payload:        payload,
		Extra:          extra,
		Digest:         sha256.Sum256([]byte("Digest")),
		SKI:            sha1.Sum([]byte("SKI")),
		ClientIP:       net.ParseIP("1.1.1.1").To4(),
		ServerIP:       net.ParseIP("2.2.2.2").To4(),
		SNI:            "SNI",
		CertID:         "SNI",
		CustomFuncName: "CustomFuncName",
		JaegerSpan:     []byte("615f730ad5fe896f:615f730ad5fe896f:1"),
		ReqContext:     reqCtx,
	}
	globalPkt := NewPacket(42, globalOp)
	gb, err := globalPkt.MarshalBinary()
	require.NoError(err)

	var globalPkt2 Packet
	globalSize, err := globalPkt2.ReadFrom(bytes.NewReader(gb))
	require.NoError(err)
	require.Equal(globalPkt.ID, globalPkt2.ID)
	require.Equal(globalOp, globalPkt2.Operation)

	// the global op should be 4 bytes smaller because it does not include an ComplianceRegion TLV
	require.Equal(size, globalSize+4)
}

func TestMLDSAOps(t *testing.T) {
	tests := []struct {
		op      Op
		value   byte
		name    string
		sigSize int
	}{
		{OpMLDSA44Sign, 0x41, "OpMLDSA44Sign", 2420},
		{OpMLDSA65Sign, 0x42, "OpMLDSA65Sign", 3309},
		{OpMLDSA87Sign, 0x43, "OpMLDSA87Sign", 4627},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)
			require.Equal(Op(tt.value), tt.op)
			require.Equal(tt.name, tt.op.String())
			require.Equal("mldsa", tt.op.Type())
			require.True(tt.op.IsMLDSASign())
			require.Equal(tt.sigSize, MLDSASignatureSize(tt.op))
		})
	}
}

func TestNonMLDSAOps(t *testing.T) {
	require := require.New(t)
	for _, op := range []Op{
		OpEd25519Sign, OpECDSASignSHA256, OpRSASignSHA256, OpRSAPSSSignSHA256,
		OpRSADecrypt, OpPing, OpError, Op(0x00),
		// 0x19 was a provisional ML-DSA value and must no longer be one; 0x40
		// and 0x44 are unused neighbours inside the reserved ML-DSA range.
		Op(0x19), Op(0x40), Op(0x44),
	} {
		require.False(op.IsMLDSASign(), "%s should not be an ML-DSA op", op)
		require.Zero(MLDSASignatureSize(op), "%s should have no ML-DSA signature size", op)
		require.NotEqual("mldsa", op.Type(), "%s should not have type mldsa", op)
	}
	// Neighbouring opcodes keep their existing names/types.
	require.Equal("OpEd25519Sign", OpEd25519Sign.String())
	require.Equal("ed25519", OpEd25519Sign.Type())
	require.Equal("Op(25)", Op(0x19).String())
	require.Equal("Op(68)", Op(0x44).String())
}

// bigOp returns an operation whose encoding exceeds paddedLength, so that no
// padding TLV is emitted and size deltas between encodings are exact.
func bigOp() Operation {
	payload := make([]byte, paddedLength+100)
	rand.Read(payload)
	return Operation{
		Opcode:  OpEd25519Sign,
		Payload: payload,
		SKI:     sha1.Sum([]byte("SKI")),
	}
}

func TestCertUsageRoundTrip(t *testing.T) {
	scopes := map[string]string{
		"example": "example",
		"empty":   "",
		"unicode": "exämple-スコープ-🚀",
		"long":    string(bytes.Repeat([]byte("p"), 4000)),
	}
	for name, scope := range scopes {
		for _, big := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/big=%v", name, big), func(t *testing.T) {
				require := require.New(t)
				op := Operation{Opcode: OpEd25519Sign, SKI: sha1.Sum([]byte("SKI"))}
				if big {
					op = bigOp()
				}
				op.CertUsage = &CertUsage{Usage: CertUsageServiceServer, Scope: scope}

				b, err := op.MarshalBinary()
				require.NoError(err)
				require.Equal(int(op.Bytes()), len(b))

				var got Operation
				require.NoError(got.UnmarshalBinary(b))
				require.NotNil(got.CertUsage)
				require.Equal(*op.CertUsage, *got.CertUsage)
				require.Equal(op, got)

				// Also through the full Packet path.
				pkt := NewPacket(7, op)
				pb, err := pkt.MarshalBinary()
				require.NoError(err)
				var pkt2 Packet
				_, err = pkt2.ReadFrom(bytes.NewReader(pb))
				require.NoError(err)
				require.Equal(op, pkt2.Operation)
			})
		}
	}
}

func TestCertUsageAbsent(t *testing.T) {
	require := require.New(t)
	for _, op := range []Operation{{Opcode: OpEd25519Sign}, bigOp()} {
		b, err := op.MarshalBinary()
		require.NoError(err)
		require.Equal(int(op.Bytes()), len(b))

		var got Operation
		require.NoError(got.UnmarshalBinary(b))
		require.Nil(got.CertUsage)
		require.Equal(op, got)
	}
}

func TestCertUsageSizeDelta(t *testing.T) {
	for _, scope := range []string{"", "example", "exämple-🚀", string(bytes.Repeat([]byte("x"), 300))} {
		require := require.New(t)
		without := bigOp()
		with := without
		with.CertUsage = &CertUsage{Usage: CertUsageServiceServer, Scope: scope}

		bWithout, err := without.MarshalBinary()
		require.NoError(err)
		bWith, err := with.MarshalBinary()
		require.NoError(err)

		require.Equal(int(without.Bytes()), len(bWithout))
		require.Equal(int(with.Bytes()), len(bWith))
		// TLV header (3) + usage byte (1) + scope bytes.
		require.Equal(3+1+len(scope), len(bWith)-len(bWithout))
		require.Equal(3+1+len(scope), int(with.Bytes())-int(without.Bytes()))
	}
}

func TestCertUsageWire(t *testing.T) {
	require := require.New(t)
	op := Operation{Opcode: OpEd25519Sign, CertUsage: &CertUsage{Usage: CertUsageServiceServer, Scope: "example"}}
	b, err := op.MarshalBinary()
	require.NoError(err)
	want := []byte{byte(TagCertUsage), 0x00, 0x08, 0x01, 'e', 'x', 'a', 'm', 'p', 'l', 'e'}
	require.True(bytes.Contains(b, want), "encoding %x does not contain %x", b, want)
}

func TestCertUsageDuplicate(t *testing.T) {
	require := require.New(t)
	var body []byte
	body = append(body, tlvBytes(TagOpcode, []byte{byte(OpEd25519Sign)})...)
	body = append(body, tlvBytes(TagCertUsage, []byte{byte(CertUsageServiceServer), 'a'})...)
	body = append(body, tlvBytes(TagCertUsage, []byte{byte(CertUsageServiceServer), 'b'})...)

	var op Operation
	err := op.UnmarshalBinary(body)
	require.Error(err)
	require.Contains(err.Error(), "seen multiple times")
}

func TestCertUsageZeroLength(t *testing.T) {
	require := require.New(t)
	var body []byte
	body = append(body, tlvBytes(TagOpcode, []byte{byte(OpEd25519Sign)})...)
	body = append(body, tlvBytes(TagCertUsage, nil)...)

	var op Operation
	require.Error(op.UnmarshalBinary(body))
}

func TestCertUsageUsageOnly(t *testing.T) {
	// A usage byte with no scope is structurally valid; rejecting an empty
	// scope is a semantic decision left to the validator.
	require := require.New(t)
	body := tlvBytes(TagCertUsage, []byte{byte(CertUsageServiceServer)})

	var op Operation
	require.NoError(op.UnmarshalBinary(body))
	require.Equal(&CertUsage{Usage: CertUsageServiceServer, Scope: ""}, op.CertUsage)
}

func TestCertUsageUnknownUsage(t *testing.T) {
	require := require.New(t)
	op := Operation{Opcode: OpEd25519Sign, CertUsage: &CertUsage{Usage: CertUsageType(0x7F), Scope: "example"}}
	b, err := op.MarshalBinary()
	require.NoError(err)

	var got Operation
	require.NoError(got.UnmarshalBinary(b))
	require.Equal(CertUsageType(0x7F), got.CertUsage.Usage)
	require.Equal("example", got.CertUsage.Scope)
	require.Equal("CertUsageType(127)", got.CertUsage.Usage.String())
}

func TestUnknownTagsSkipped(t *testing.T) {
	for _, tag := range []Tag{0x30, 0xFE} {
		t.Run(tag.String(), func(t *testing.T) {
			require := require.New(t)
			var body []byte
			body = append(body, tlvBytes(TagOpcode, []byte{byte(OpEd25519Sign)})...)
			body = append(body, tlvBytes(tag, []byte("unknown"))...)
			body = append(body, tlvBytes(TagCertUsage, []byte{byte(CertUsageServiceServer), 'e', 'x', 'a', 'm', 'p', 'l', 'e'})...)
			// Repeated unknown tags are not duplicate-tracked.
			body = append(body, tlvBytes(tag, []byte("again"))...)

			var op Operation
			require.NoError(op.UnmarshalBinary(body))
			require.Equal(OpEd25519Sign, op.Opcode)
			require.Equal(&CertUsage{Usage: CertUsageServiceServer, Scope: "example"}, op.CertUsage)
		})
	}
}

func TestCertUsageNoAlias(t *testing.T) {
	require := require.New(t)
	op := Operation{Opcode: OpEd25519Sign, CertUsage: &CertUsage{Usage: CertUsageServiceServer, Scope: "example"}}
	b, err := op.MarshalBinary()
	require.NoError(err)

	var got Operation
	require.NoError(got.UnmarshalBinary(b))

	// Overwrite the entire input buffer; the decoded CertUsage must be unaffected.
	for i := range b {
		b[i] = 0xAA
	}
	require.Equal(CertUsageServiceServer, got.CertUsage.Usage)
	require.Equal("example", got.CertUsage.Scope)
}

func TestCertUsageString(t *testing.T) {
	require := require.New(t)
	op := Operation{Opcode: OpEd25519Sign}
	require.NotContains(op.String(), "CertUsage")

	op.CertUsage = &CertUsage{Usage: CertUsageServiceServer, Scope: "example"}
	s := op.String()
	require.Contains(s, `CertUsage: {Usage: CertUsageServiceServer, Scope: "example"}`)
	require.True(strings.HasSuffix(s, "]"))
	require.Equal("TagCertUsage", TagCertUsage.String())
	require.Equal("<nil>", (*CertUsage)(nil).String())
}
