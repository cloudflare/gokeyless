package conn

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cloudflare/gokeyless/internal/protocol"
)

const defaultOpTimeout = 10 * time.Second

// ErrClosed is the error returned when an already-closed connection is re-used.
var ErrClosed = fmt.Errorf("use of closed connection")

// Conn represents an open keyless connection.
type Conn struct {
	// In order to read, acquire readMtx; in order to write, acquire writeMtx
	conn net.Conn
	// In order to read, acquire mapMtx.RLock(); in order to write, acquire
	// mapMtx.Lock().
	listeners map[uint32]chan *protocol.Operation
	// In order to modify, acquire mapMtx.Lock().
	nextID uint32

	opTimeout time.Duration

	// If you're going to acquire all three, always acquire in the following order
	// to avoid deadlock: readMtx, writeMtx, mapMtx.
	readMtx, writeMtx sync.Mutex
	mapMtx            sync.RWMutex

	// In order to read, acquire any mutex. In order to modify, acquire all three.
	closed bool
}

// NewConnTimeout constructs a new Conn with the given operation timeout.
func NewConnTimeout(inner net.Conn, opTimeout time.Duration) *Conn {
	return &Conn{
		conn:      inner,
		listeners: make(map[uint32]chan *protocol.Operation),
		opTimeout: opTimeout,
	}
}

// NewConn constructs a new Conn with the default operation timeout of 10s.
func NewConn(inner net.Conn) *Conn {
	return NewConnTimeout(inner, defaultOpTimeout)
}

// Close closes the connection and causes all outstanding operations to fail.
func (c *Conn) Close() error {
	c.readMtx.Lock()
	c.writeMtx.Lock()
	c.mapMtx.Lock()
	if c.closed {
		c.mapMtx.Unlock()
		c.writeMtx.Unlock()
		c.readMtx.Unlock()
		return ErrClosed
	}

	c.closed = true
	err := c.conn.Close()
	for _, l := range c.listeners {
		// signal to all of the blocking calls to DoOperation that they should
		// return
		l <- nil
	}

	c.mapMtx.Unlock()
	c.writeMtx.Unlock()
	c.readMtx.Unlock()
	return err
}

// DoRead reads a packet from the connection and sends it to its intended
// recipient. On the client side, this should be called repeatedly. Each time it
// returns, the corresponding DoOperation call will stop blocking and return the
// response.
func (c *Conn) DoRead() error {
	c.readMtx.Lock()
	if c.closed {
		c.readMtx.Unlock()
		return ErrClosed
	}

	pkt := new(protocol.Packet)
	_, err := pkt.ReadFrom(c.conn)
	c.readMtx.Unlock()
	if err != nil {
		return err
	}

	c.mapMtx.RLock()
	if c.closed {
		// it was closed in the time that we didn't have a lock held
		c.mapMtx.RUnlock()
		return ErrClosed
	}

	// NOTE: Regardless of what happens, it's the writer's responsibility - not
	// ours - to delete their channel after they receive their response. If we
	// were to do that ourselves, we could introduce a race condition:
	// - Writer times out, enters timeout case in select block
	// - Reader locks the map mutex, finds their channel, sends them the response,
	//   and deletes the channel from the map.
	// - Another writer comes, gets the same ID as the currently sleeping waiter,
	//   and writes their channel into the map.
	// - The waiter that timed out wakes back up and deletes the wrong channel!

	l, ok := c.listeners[pkt.ID]
	c.mapMtx.RUnlock()
	if !ok {
		// the call to DoOperation hit its timeout and cleared the map and returned;
		// the error was delivered from that call, so no point in delivering it here
		// too
		return nil
	}

	l <- &pkt.Operation
	return nil
}

// DoOperation executes an entire keyless operation, returning its result.
func (c *Conn) DoOperation(op protocol.Operation) (*protocol.Operation, error) {
	response := make(chan *protocol.Operation, 1)

	c.mapMtx.Lock()
	if c.closed {
		c.mapMtx.Unlock()
		return nil, ErrClosed
	}
	id := c.nextID
	c.nextID++
	if _, ok := c.listeners[id]; ok {
		c.mapMtx.Unlock()
		// TODO: If this becomes an issue in practice, we could consider randomly
		// generating IDs and spinning until we find an available one.
		return nil, fmt.Errorf("could not allocate new packet ID: packet IDs wrapped around - this indicates a very fast client or a very slow server")
	}
	c.listeners[id] = response
	c.mapMtx.Unlock()

	pkt := protocol.NewPacket(id, op)

	c.writeMtx.Lock()
	if c.closed {
		// it was closed in the time that we didn't have a lock held
		c.writeMtx.Unlock()
		return nil, ErrClosed
	}
	end := time.Now().Add(c.opTimeout)
	err := c.conn.SetWriteDeadline(end)
	if err != nil {
		c.writeMtx.Unlock()
		return nil, fmt.Errorf("could not set write deadline: %v", err)
	}
	_, err = pkt.WriteTo(c.conn)
	c.writeMtx.Unlock()
	if err != nil {
		return nil, fmt.Errorf("could not write to connection: %v", err)
	}

	left := end.Sub(time.Now())
	select {
	case op := <-response:
		c.mapMtx.Lock()
		delete(c.listeners, id)
		c.mapMtx.Unlock()
		if op == nil {
			return nil, ErrClosed
		}
		return op, nil
	case <-time.After(left):
		c.mapMtx.Lock()
		delete(c.listeners, id)
		c.mapMtx.Unlock()
		return nil, fmt.Errorf("operation timed out")
	}
}

// Ping sends a ping message over the connection and waits for a corresponding
// Pong response from the server.
func (c *Conn) Ping(data []byte) error {
	result, err := c.DoOperation(protocol.Operation{
		Opcode:  protocol.OpPing,
		Payload: data,
	})
	if err != nil {
		return err
	}

	switch result.Opcode {
	case protocol.OpPong:
		if bytes.Compare(data, result.Payload) != 0 {
			return fmt.Errorf("ping: got mismatched response payload: 0x%x != 0x%x", result.Payload, data)
		}
		return nil
	case protocol.OpError:
		return result.GetError()
	default:
		return fmt.Errorf("ping: got unexpected response opcode: %v", result.Opcode)
	}
}
