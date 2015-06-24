package gokeyless

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
)

// Conn represents an open keyless connection.
type Conn struct {
	net.Conn
	IsOpen  bool
	cond    *sync.Cond
	headers map[uint32]*Header
}

// NewConn initializes a new Conn
func NewConn(inner net.Conn) *Conn {
	return &Conn{
		Conn:    inner,
		IsOpen:  true,
		cond:    sync.NewCond(new(sync.Mutex)),
		headers: make(map[uint32]*Header),
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

func (c *Conn) queueRead() {
	h, err := c.ReadHeader()
	if err != nil {
		log.Printf("Error reading header: %v", err)
		return
	}

	c.cond.L.Lock()
	c.headers[h.ID] = h
	c.cond.L.Unlock()
	c.cond.Broadcast()
}

// ListenResponse attempts to read a response with the appropriate ID, blocking until it is available.
func (c *Conn) ListenResponse(id uint32) (*Header, error) {
	go c.queueRead()
	c.cond.L.Lock()
	defer c.cond.L.Unlock()

	for c.headers[id] == nil {
		c.cond.Wait()
	}

	h := c.headers[id]
	delete(c.headers, id)
	return h, nil
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

// KeyOperation performs an opaque cryptographic operation with the given digested key.
func (c *Conn) KeyOperation(op Op, msg []byte, dgst Digest) ([]byte, error) {
	result, err := c.DoOperation(&Operation{
		Opcode:  op,
		Payload: msg,
		Dgst:    dgst,
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
