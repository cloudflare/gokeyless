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
	tls.Conn
	sync.Mutex
	users     uint32
	listeners map[uint32]chan *Header
}

// NewConn initializes a new Conn
func NewConn(inner *tls.Conn) *Conn {
	return &Conn{
		Conn:      *inner,
		users:     1,
		listeners: make(map[uint32]chan *Header),
	}
}

// Use marks conn as used by the current goroutine, returning ok if the Conn is open.
// This should be accompanied by a later Close() call.
func (c *Conn) Use() bool {
	c.Lock()
	defer c.Unlock()
	if c.users == 0 {
		return false
	}
	c.users++
	return true
}

// Close marks conn as closed and closed the inner net.Conn.
func (c *Conn) Close() {
	c.Lock()
	defer c.Unlock()
	c.users--
	if c.users == 0 {
		if err := c.Conn.Close(); err != nil {
			log.Errorf("Unable to close connection: %v", err)
		}
	}
}

// IsClosed returns true if the connection has been closed.
func (c *Conn) IsClosed() bool {
	c.Lock()
	defer c.Unlock()
	return c.users == 0
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
	c.Lock()
	defer c.Unlock()
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
	peerCerts := c.ConnectionState().PeerCertificates
	if len(peerCerts) > 0 && len(peerCerts[0].AuthorityKeyId) == len(h.Body.AKI) {
		copy(h.Body.AKI[:], peerCerts[0].AuthorityKeyId)
	}
	return h, nil
}

func (c *Conn) doRead() error {
	h, err := c.ReadHeader()
	if err != nil {
		return err
	}

	c.Lock()
	if _, ok := c.listeners[h.ID]; !ok {
		c.listeners[h.ID] = make(chan *Header, 1)
	}
	c.Unlock()

	c.listeners[h.ID] <- h

	return nil
}

// listenResponse attempts to read a response with the appropriate ID, blocking until it is available.
func (c *Conn) listenResponse(id uint32) (*Header, error) {
	c.Lock()
	if _, ok := c.listeners[id]; !ok {
		c.listeners[id] = make(chan *Header, 1)
	}
	c.Unlock()

	defer func() {
		c.Lock()
		close(c.listeners[id])
		delete(c.listeners, id)
		c.Unlock()
	}()

	if err := c.doRead(); err != nil {
		return nil, err
	}

	return <-c.listeners[id], nil
}

// DoOperation excutes an entire keyless operation, returning its result.
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
