package protocol

import (
	"crypto/sha1"
	"crypto/sha256"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMarshalBinary(t *testing.T) {
	require := require.New(t)

	op := Operation{
		Opcode:         OpECDSASignSHA256,
		Payload:        []byte("Payload"),
		Extra:          []byte("Extra"),
		Digest:         sha256.Sum256([]byte("Digest")),
		SKI:            sha1.Sum([]byte("SKI")),
		ClientIP:       net.ParseIP("1.1.1.1").To4(),
		ServerIP:       net.ParseIP("2.2.2.2").To4(),
		SNI:            "SNI",
		CertID:         "SNI",
		CustomFuncName: "CustomFuncName",
	}
	pkt := NewPacket(42, op)
	b, err := pkt.MarshalBinary()
	require.NoError(err)

	var pkt2 Packet
	err = pkt2.UnmarshalBinary(b)
	require.NoError(err)
	require.Equal(pkt.ID, pkt2.ID)
	require.Equal(op, pkt2.Operation)
}
