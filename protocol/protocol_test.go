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
	pkt := NewPacket(42, op)
	b, err := pkt.MarshalBinary()
	require.NoError(err)

	var pkt2 Packet
	_, err = pkt2.ReadFrom(bytes.NewReader(b))
	require.NoError(err)
	require.Equal(pkt.ID, pkt2.ID)
	require.Equal(op, pkt2.Operation)
}

func FuzzUnmarshalBinary(f *testing.F) {

	f.Fuzz(func(t *testing.T, data []byte) {
		var p Packet
		_ = p.UnmarshalBinary(data)
	})
}

func FuzzReadFrom(f *testing.F) {

	f.Fuzz(func(t *testing.T, data []byte) {
		var pkt2 Packet
		pkt2.ReadFrom(bytes.NewReader(data))
	})
}
