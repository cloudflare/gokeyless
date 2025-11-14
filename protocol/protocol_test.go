package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"net"
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
	pkt, err := NewPacket(42, op)
	require.NoError(err)
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
	globalPkt, err := NewPacket(42, globalOp)
	require.NoError(err)
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

func TestTLVMaxLengthExceeded(t *testing.T) {
	require := require.New(t)

	// Create an operation with a payload that exceeds the TLV maximum length
	// TLV max data length is math.MaxUint16 - 3 = 65533 bytes
	// We'll use 65534 bytes to trigger the error
	oversizedPayload := make([]byte, 65534)
	op := Operation{
		Opcode:  OpECDSASignSHA256,
		Payload: oversizedPayload,
	}

	// Attempting to create a packet should fail with an error
	_, err := NewPacket(42, op)
	require.Error(err, "Expected error when payload exceeds TLV maximum length")
	require.Contains(err.Error(), "data exceeds TLV maximum length", "Error message should mention TLV maximum length")
}

func TestOperationBytesMaxLengthExceeded(t *testing.T) {
	require := require.New(t)

	// Test that Operation.Bytes() returns an error for oversized data
	oversizedPayload := make([]byte, 65534)
	op := Operation{
		Opcode:  OpRSADecrypt,
		Payload: oversizedPayload,
	}

	_, err := op.Bytes()
	require.Error(err, "Expected error when calling Bytes() on operation with oversized payload")
	require.Contains(err.Error(), "data exceeds TLV maximum length")
}
