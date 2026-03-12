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

func TestAddOperationRequestID_NonStringTypes(t *testing.T) {
	nonStringValues := []struct {
		name  string
		value interface{}
	}{
		{"number", 12345},
		{"float", 3.14},
		{"bool", true},
		{"null", nil},
		{"array", []interface{}{1, 2, 3}},
		{"object", map[string]interface{}{"nested": "value"}},
	}

	for _, tc := range nonStringValues {
		t.Run(tc.name, func(t *testing.T) {
			rc := map[string]interface{}{"request_id": tc.value}
			b, err := json.Marshal(rc)
			require.NoError(t, err)

			op := protocol.Operation{
				Opcode:     protocol.OpECDSASignSHA224,
				Payload:    []byte("test"),
				ReqContext: b,
			}

			// Must not panic; should fall through to generate a new UUID
			reqID := addOperationRequestID(&op)
			require.NotEmpty(t, reqID)
		})
	}
}

func TestGetOperationRequestID(t *testing.T) {
	require := require.New(t)

	// Valid string request_id
	rc := map[string]interface{}{"request_id": "abc-123"}
	b, err := json.Marshal(rc)
	require.NoError(err)
	op := protocol.Operation{ReqContext: b}
	reqID, err := getOperationRequestID(&op)
	require.NoError(err)
	require.Equal("abc-123", reqID)

	// Empty ReqContext
	op.ReqContext = nil
	reqID, err = getOperationRequestID(&op)
	require.NoError(err)
	require.Empty(reqID)

	// Malformed JSON
	op.ReqContext = []byte("not json")
	reqID, err = getOperationRequestID(&op)
	require.Error(err)
	require.Empty(reqID)
}

func TestGetOperationRequestID_NonStringTypes(t *testing.T) {
	nonStringValues := []struct {
		name  string
		value interface{}
	}{
		{"number", 12345},
		{"float", 3.14},
		{"bool", true},
		{"null", nil},
		{"array", []interface{}{1, 2, 3}},
		{"object", map[string]interface{}{"nested": "value"}},
	}

	for _, tc := range nonStringValues {
		t.Run(tc.name, func(t *testing.T) {
			rc := map[string]interface{}{"request_id": tc.value}
			b, err := json.Marshal(rc)
			require.NoError(t, err)

			op := protocol.Operation{ReqContext: b}

			// Must not panic; should return empty string with no error
			reqID, err := getOperationRequestID(&op)
			require.NoError(t, err)
			require.Empty(t, reqID)
		})
	}
}
