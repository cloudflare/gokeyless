package protocol

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRespond(t *testing.T) {
	tests := []struct {
		name                  string
		payloadSize           int
		expectedTotalByteSize int64
		expectedLengthHeader  uint16
	}{
		{
			name:                  "minimum packet size is 1024",
			payloadSize:           1000,
			expectedTotalByteSize: 1024,
			expectedLengthHeader:  1016, // minimum size - header or payload tlv + opcode tlv + padding
		},
		{
			name:                  "packet size over 1024 bytes",
			payloadSize:           2000,
			expectedTotalByteSize: 2015, // payload TLV + 4 bytes for the Opcode + 8 bytes for header
			expectedLengthHeader:  2007, // expectedTotalByteSize - header
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require := require.New(t)

			var buf bytes.Buffer
			payload := make([]byte, tt.payloadSize)
			rand.Read(payload)

			Respond(&buf, 1, payload)

			var pkt Packet
			size, err := pkt.ReadFrom(&buf)
			require.NoError(err)
			require.Equal(tt.expectedTotalByteSize, size)
			require.Equal(tt.expectedLengthHeader, pkt.Length)
			// the only two non-header fields on the response should be Opcode and Payload
			// if other fields are added, it can be a breaking change for the client depending
			// the implementation of the protocol.
			require.NotEmpty(pkt.Opcode)
			require.NotEmpty(pkt.Payload)

			require.Empty(pkt.Extra)
			require.Empty(pkt.SKI)
			require.Empty(pkt.Digest)
			require.Empty(pkt.ClientIP)
			require.Empty(pkt.ServerIP)
			require.Empty(pkt.SNI)
			require.Empty(pkt.CertID)
			require.Empty(pkt.ForwardingSvc)
			require.Empty(pkt.CustomFuncName)
			require.Empty(pkt.JaegerSpan)
			require.Empty(pkt.ReqContext)
			require.Empty(pkt.ComplianceRegion)
		})
	}
}
