package server

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/cloudflare/gokeyless/protocol"
	"github.com/stretchr/testify/require"
)

func TestRequestID(t *testing.T) {
	require := require.New(t)

	r := make([]byte, 20)
	_, err := rand.Read(r)
	require.NoError(err)

	// empty byte array in ReqContext
	op := protocol.Operation{
		Opcode:     protocol.OpECDSASignSHA224,
		Payload:    r,
		ReqContext: []byte{},
	}
	reqID := addOperationRequestID(&op)
	require.NotEqual(reqID, "")

	// nil byte array
	op.ReqContext = nil
	reqID = addOperationRequestID(&op)
	require.NotEqual(reqID, "")

	// Operation.ReqContext contains a map and request id
	rc := map[string]interface{}{"request_id": "b76dfaf1-a852-4dc2-98ff-0ba1947a82b6"}
	b, err := json.Marshal(rc)
	require.NoError(err)
	op.ReqContext = b
	reqID = addOperationRequestID(&op)
	require.Equal(reqID, "b76dfaf1-a852-4dc2-98ff-0ba1947a82b6")
}
