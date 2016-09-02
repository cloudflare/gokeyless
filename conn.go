package gokeyless

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"sync"

	"github.com/cloudflare/cfssl/log"
)

// Conn represents an open keyless connection.
type Conn struct {
	*tls.Conn
	listeners map[uint32]chan *Header

	read, write sync.Mutex
	mapMutex    sync.RWMutex
}

// NewConn initializes a new Conn.
func NewConn(inner *tls.Conn) *Conn {
	return &Conn{
		Conn:      inner,
		listeners: make(map[uint32]chan *Header),
	}
}

// Close marks conn as closed and closes the inner net.Conn if it is
// no longer in use.
func (c *Conn) Close() {
	c.read.Lock()
	c.write.Lock()
	defer c.read.Unlock()
	defer c.write.Unlock()

	if c.Conn != nil {
		if err := c.Conn.Close(); err != nil {
			log.Errorf("Unable to close connection: %v", err)
		}
	}
	c.Conn = nil
}

// IsClosed returns true if the connection has been closed.
func (c *Conn) IsClosed() bool {
	c.read.Lock()
	c.write.Lock()
	defer c.read.Unlock()
	defer c.write.Unlock()

	return c.Conn == nil
}

// WriteHeader marshals and header and writes it to the conn.
func (c *Conn) WriteHeader(h *Header) error {
	c.write.Lock()
	defer c.write.Unlock()

	if c.Conn == nil {
		return fmt.Errorf("connection is closed or not yet ready")
	}

	b, err := h.MarshalBinary()
	if err != nil {
		return err
	}

	_, err = c.Write(b)
	return err

}

// ReadHeader unmarshals a header from the wire into an internal
// Header structure.
func (c *Conn) ReadHeader() (*Header, error) {
	c.read.Lock()
	defer c.read.Unlock()

	if c.Conn == nil {
		return nil, fmt.Errorf("connection is closed or not yet ready")
	}

	b := make([]byte, 8)
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}

	h := new(Header)
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

func (c *Conn) doRead() error {
	h, err := c.ReadHeader()
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

// listenResponse attempts to read a response with the appropriate ID, blocking until it is available.
func (c *Conn) listenResponse(id uint32) (*Header, error) {
	c.mapMutex.Lock()
	ch, ok := c.listeners[id]
	if !ok {
		ch = make(chan *Header, 1)
		c.listeners[id] = ch
	}
	c.mapMutex.Unlock()

	defer func() {
		c.mapMutex.Lock()
		close(ch)
		delete(c.listeners, id)
		c.mapMutex.Unlock()
	}()

	if err := c.doRead(); err != nil {
		return nil, err
	}

	return <-ch, nil
}

// DoOperation executes an entire keyless operation, returning its
// result.
func (c *Conn) DoOperation(operation *Operation) (*Operation, error) {
	req := NewHeader(operation)
	if err := c.WriteHeader(req); err != nil {
		return nil, err
	}

	resp, err := c.listenResponse(req.ID)
	if err != nil {
		return nil, err
	}

	return resp.Body, nil
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

// Activate requests that the server send a hash of its API key to the client.
func (c *Conn) Activate(hashedToken []byte) error {
	result, err := c.DoOperation(&Operation{
		Opcode: OpActivate,
	})
	if err != nil {
		return err
	}

	if result.Opcode != OpResponse {
		if result.Opcode == OpError {
			return result.GetError()
		}
		return fmt.Errorf("wrong response opcode: %v", result.Opcode)
	}

	if bytes.Compare(result.Payload, hashedToken) != 0 {
		return fmt.Errorf("payload doesn't match hashed token: %v!=%v", result.Payload, hashedToken)
	}

	return nil
}

// respondOperation writes a keyless response operation to the wire.
func (c *Conn) respondOperation(id uint32, operation *Operation) error {
	resp := NewHeader(operation)
	resp.ID = id
	return c.WriteHeader(resp)
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
