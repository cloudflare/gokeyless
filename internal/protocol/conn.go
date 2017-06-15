package protocol

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"sync"
	"time"
)

// OperationTimeout is the default timeout value.
var (
	OperationTimeout = time.Second * 10
)

// Conn represents an open keyless connection.
type Conn struct {
	*tls.Conn
	listeners map[uint32]chan *Packet

	write    sync.Mutex
	mapMutex sync.RWMutex
}

// NewConn initializes a new Conn.
func NewConn(inner *tls.Conn) *Conn {
	return &Conn{
		Conn:      inner,
		listeners: make(map[uint32]chan *Packet),
	}
}

// Close marks conn as closed and closes the inner net.Conn if it is
// no longer in use.
func (c *Conn) Close() {
	c.write.Lock()
	c.Conn.Close()
	defer c.write.Unlock()
}

// WritePacket marshals packet and writes it to the conn.
func (c *Conn) WritePacket(h *Packet) error {
	c.write.Lock()
	defer c.write.Unlock()

	b, err := h.MarshalBinary()
	if err != nil {
		return err
	}

	_, err = c.Write(b)
	return err
}

// ReadPacket unmarshals a packet from the wire into an internal
// Packet structure.
func (c *Conn) ReadPacket() (*Packet, error) {
	b := make([]byte, 8)
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}

	h := new(Packet)
	h.UnmarshalBinary(b)

	body := make([]byte, h.Length)
	if _, err := io.ReadFull(c, body); err != nil {
		return nil, err
	}

	h.Body = new(Operation)
	if err := h.Body.UnmarshalBinary(body); err != nil {
		return nil, err
	}
	return h, nil
}

// DoRead reads a packet from the connection and sends it to its intended
// recipient. On the client side, this should be called repeatedly. Each time it
// returns, the corresponding DoOperation call will stop blocking and return the
// response.
func (c *Conn) DoRead() error {
	h, err := c.ReadPacket()
	if err != nil {
		return err
	}

	c.mapMutex.RLock()
	ch, ok := c.listeners[h.ID]
	if ok {
		ch <- h
	}
	c.mapMutex.RUnlock()

	return nil
}

// DoOperation executes an entire keyless operation, returning its
// result.
func (c *Conn) DoOperation(operation *Operation) (*Operation, error) {
	req := NewPacket(operation)

	// Must have channel entry ready before sending request since
	// response may be acquired by reader goroutine immediately
	// and if the channel cannot be found, the response will be lost.
	id := req.ID
	ch := make(chan *Packet, 1)
	c.mapMutex.Lock()
	c.listeners[id] = ch
	c.mapMutex.Unlock()

	defer func() {
		c.mapMutex.Lock()
		delete(c.listeners, id)
		c.mapMutex.Unlock()
	}()

	start := time.Now()
	if err := c.WritePacket(req); err != nil {
		return nil, err
	}

	select {
	case resp := <-ch:
		return resp.Body, nil

	case <-time.After(OperationTimeout - time.Since(start)):
		return nil, fmt.Errorf("operation timeout")
	}
}

// Ping requests that the server reflect the data back to the client.
func (c *Conn) Ping(data []byte) error {
	result, err := c.DoOperation(&Operation{
		Opcode:  OpPing,
		Payload: data,
	})
	if err != nil {
		return err
	}

	if result.Opcode != OpPong {
		if result.Opcode == OpError {
			return result.GetError()
		}
		return fmt.Errorf("wrong response opcode: %v", result.Opcode)
	}

	if bytes.Compare(data, result.Payload) != 0 {
		return fmt.Errorf("payloads don't match: %v!=%v", data, result.Payload)
	}

	return nil
}

// respondOperation writes a keyless response operation to the wire.
func (c *Conn) respondOperation(id uint32, operation *Operation) error {
	resp := NewPacket(operation)
	resp.ID = id
	return c.WritePacket(resp)
}

// Respond sends a keyless response.
func (c *Conn) Respond(id uint32, payload []byte) error {
	return c.respondOperation(
		id,
		&Operation{
			Opcode:  OpResponse,
			Payload: payload,
		})
}

// RespondPong responds to a keyless Ping operation.
func (c *Conn) RespondPong(id uint32, payload []byte) error {
	return c.respondOperation(
		id,
		&Operation{
			Opcode:  OpPong,
			Payload: payload,
		})
}

// RespondError sends a keyless error response.
func (c *Conn) RespondError(id uint32, err Error) error {
	return c.respondOperation(
		id,
		&Operation{
			Opcode:  OpError,
			Payload: []byte{byte(err)},
		})
}
