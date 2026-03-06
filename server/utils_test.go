package server

import (
	"crypto/rand"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/gokeyless/protocol"
	"github.com/stretchr/testify/require"

	"golang.org/x/sync/semaphore"
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

// panicSealer is a Sealer implementation that always panics.
// Used to test that handler.handle() recovers from panics in the request path.
type panicSealer struct{}

func (p panicSealer) Seal(*protocol.Operation) ([]byte, error)   { panic("test panic in Seal") }
func (p panicSealer) Unseal(*protocol.Operation) ([]byte, error) { panic("test panic in Unseal") }

// TestHandlePanicRecovery verifies that handler.handle() recovers from a panic
// instead of crashing the process or leaking a semaphore token. This is a
// defense-in-depth measure: any unrecovered panic in a handler goroutine would
// terminate the entire gokeyless server.
func TestHandlePanicRecovery(t *testing.T) {
	s := &Server{
		config: DefaultServeConfig(),
		keys:   NewDefaultKeystore(),
		sealer: panicSealer{},
	}

	// Use a pipe so we have a valid net.Conn that handle() can write to.
	serverConn, _ := net.Pipe()
	defer serverConn.Close()

	// The semaphore token is acquired by loop() before spawning handle().
	// Simulate that by creating a semaphore with capacity 1 and acquiring it.
	tokens := semaphore.NewWeighted(1)
	require.True(t, tokens.TryAcquire(1), "should be able to acquire initial token")

	h := &handler{
		name:    "test-panic-recovery",
		s:       s,
		tokens:  tokens,
		conn:    serverConn,
		timeout: 5 * time.Second,
		c:       &ClientInfo{},
	}

	// Send an OpSeal request. The panicSealer will panic inside unlimitedDo,
	// exercising the recover() in handle().
	pkt := &protocol.Packet{
		Header: protocol.Header{
			MajorVers: 0x01,
			MinorVers: 0x00,
			ID:        1,
		},
		Operation: protocol.Operation{
			Opcode:  protocol.OpSeal,
			Payload: []byte("test payload"),
		},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.handle(pkt, time.Now())
	}()

	// Wait for handle to finish — it should return normally via recover().
	select {
	case <-done:
		// success: handle() recovered from the panic
	case <-time.After(5 * time.Second):
		t.Fatal("handle() did not return — possible deadlock or unrecovered panic")
	}

	// The semaphore token must have been released by the recover() path.
	// If the token leaked, this would fail.
	if !tokens.TryAcquire(1) {
		t.Fatal("semaphore token was not released after panic recovery")
	}
}

// TestHandleNoPanicReleasesToken verifies that under normal (non-panic)
// operation, handle() still correctly releases the semaphore token.
func TestHandleNoPanicReleasesToken(t *testing.T) {
	s := &Server{
		config:     DefaultServeConfig(),
		keys:       NewDefaultKeystore(),
		dispatcher: nil,
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	// Drain responses from the server side so WriteTo doesn't block.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := clientConn.Read(buf); err != nil {
				return
			}
		}
	}()
	defer clientConn.Close()

	tokens := semaphore.NewWeighted(1)
	require.True(t, tokens.TryAcquire(1))

	h := &handler{
		name:    "test-normal-token-release",
		s:       s,
		tokens:  tokens,
		conn:    serverConn,
		timeout: 5 * time.Second,
		c:       &ClientInfo{},
	}

	// A simple OpPing with no ReqContext — should not panic.
	pkt := &protocol.Packet{
		Header: protocol.Header{
			MajorVers: 0x01,
			MinorVers: 0x00,
			ID:        1,
		},
		Operation: protocol.Operation{
			Opcode:  protocol.OpPing,
			Payload: []byte("ping"),
		},
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.handle(pkt, time.Now())
	}()
	wg.Wait()

	if !tokens.TryAcquire(1) {
		t.Fatal("semaphore token was not released after normal handle()")
	}
}
