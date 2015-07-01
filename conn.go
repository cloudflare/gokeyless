package gokeyless

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
)

// Conn represents an open keyless connection.
type Conn struct {
	net.Conn
	sync.Mutex
	IsOpen    bool
	listeners map[uint32]chan *Header
}

// NewConn initializes a new Conn
func NewConn(inner net.Conn) *Conn {
	return &Conn{
		Conn:      inner,
		IsOpen:    true,
		listeners: make(map[uint32]chan *Header),
	}
}

// Close marks conn as closed and closed the inner net.Conn.
func (c *Conn) Close() {
	c.IsOpen = false
	c.Conn.Close()
}

// WriteHeader marshals and header and writes it to the conn.
func (c *Conn) WriteHeader(h *Header) error {
	b, err := h.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = c.Write(b)
	return err
}

// ReadHeader unmarhals a header from the wire into the internal Header structure.
func (c *Conn) ReadHeader() (*Header, error) {
	b := make([]byte, 8)
	if _, err := c.Read(b); err != nil {
		return nil, err
	}

	h := new(Header)
	h.UnmarshalBinary(b)

	body := make([]byte, h.Length)
	if _, err := c.Read(body); err != nil {
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

	c.Lock()
	defer c.Unlock()

	l, ok := c.listeners[h.ID]
	if !ok {
		return fmt.Errorf("read unqueued header with id: %v", h.ID)
	}

	l <- h

	delete(c.listeners, h.ID)
	close(l)
	return nil
}

// ListenResponse attempts to read a response with the appropriate ID, blocking until it is available.
func (c *Conn) ListenResponse(id uint32) (*Header, error) {
	l := make(chan *Header, 1)

	c.Lock()
	c.listeners[id] = l
	c.Unlock()

	if err := c.doRead(); err != nil {
		c.Lock()
		delete(c.listeners, id)
		c.Unlock()
		close(l)
		return nil, err
	}

	return <-l, nil
}

// DoOperation excutes an entire keyless operation, returning its result.
func (c *Conn) DoOperation(operation *Operation) (*Operation, error) {
	req := NewHeader(operation)
	if err := c.WriteHeader(req); err != nil {
		return nil, err
	}

	resp, err := c.ListenResponse(req.ID)
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

// KeyOperation performs an opaque cryptographic operation with the given SKIed key.
func (c *Conn) KeyOperation(op Op, msg []byte, ski SKI, digest Digest) ([]byte, error) {
	result, err := c.DoOperation(&Operation{
		Opcode:  op,
		Payload: msg,
		SKI:     ski,
		Digest:  digest,
	})
	if err != nil {
		return nil, err
	}

	if result.Opcode != OpResponse {
		if result.Opcode == OpError {
			return nil, result.GetError()
		}
		return nil, fmt.Errorf("wrong response opcode: %v", result.Opcode)
	}

	if len(result.Payload) == 0 {
		return nil, errors.New("empty payload")
	}

	return result.Payload, nil
}
