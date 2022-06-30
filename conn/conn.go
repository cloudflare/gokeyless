// Package conn provides a high-level wrapper around a connection to a Keyless
// server. It abstracts the details of synchronization and provides a
// thread-safe interface for sending messages and receiving responses.
package conn

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cloudflare/gokeyless/protocol"
	"github.com/cloudflare/gokeyless/tracing"
	"github.com/opentracing/opentracing-go"
)

// The Conn type implemented here contains a single network connection to a
// Keyless server. It supports writing messages to the server, reading messages
// from the server, and dispatching responses to the appropriate client.
//
// Interacting with the Network Connection
///
// While the net.Conn interface is, strictly-speaking, thread-safe, it's not
// good enough for our needs. In particular, if two goroutines read or write to
// or from the connection at the same time, the net.Conn object will not crash,
// but it may write the bytes of the two goroutines' payloads interleaved or
// return different bits of each message payload to the reader goroutines.
//
// However, so long as there is only one goroutine reading and one goroutine
// writing at a time, we are fine since reading and writing to not interfere
// with one another. Thus, we protect the connection with two mutexes - one for
// reading and one for writing. This protects us from concurrency errors while
// also maintaining the performance of having reading and writing occur
// independently of one another.
//
// Receiving Responses
//
// The Keyless protocol allows messages to be sent with a unique ID, and
// responses may be sent in any order - the ID on the response allows the client
// to match a response to its corresponding request. In order to take advantage
// of this, we allow for there to be many outstanding requests at a time.
//
// When DoOperation method is called, a packet is constructed for the given
// operation. In order to reduce the likelihood of ID collisions, IDs are
// allocated sequentially so that a collision can only happen if 2^32 requests
// are outstanding at a given time, and the ID wraps around to an existing
// outstanding identifier.
//
// First, a channel is created over which the response to the message will be
// sent. A connection-global map of channels (the 'listeners' map) is kept,
// protected by a read-write mutex. A write lock is acquired, and the channel
// is added to the map.
//
// At this point, the map mutex is dropped in order to allow other goroutines
// to use it. The mutex protecting writing to the connection is acquired, the
// packet is written to the connection, and the mutex is released.
//
// Now the goroutine simply waits for a response on the channel, or for a
// timeout. In either case, it is that goroutine's responsibility to remove its
// channel from the map after it has completed. If any other goroutine were to
// remove its channel from the map, a race condition could be introduced (for
// details, see the comment in DoRead).
//
// Reading Responses
//
// In order to read responses from the connection, the DoRead method is called
// in a loop. It acquires the read mutex, reads a message off the connection,
// and dispatches it to the appropriate listener.
//
// Closing the Connection
//
// Ideally, a client would only close the connection after all of its other
// outstanding operations were complete. However, it would be brittle to rely on
// this behavior for correctness. Thus, we support closing the connection in any
// state.
//
// The channel's open/closed state is marked by a single 'closed' boolean. In
// order to read this field, any mutex (in any state - read lock or write lock)
// must be acquired. This allows any method, after performing any
// synchronization at all, to check for the channel being closed and to abort
// with the appropriate error (ErrClosed). Because any mutex allows reading the
// 'closed' field, /every/ mutex (in write mode) must be acquired in order to
// modify it.
//
// The Close method first marks the connection as closed by setting 'close' to
// true. Then, it iterates over all of the channels in the listeners map, and
// sends a nil value to each to signal that the connection is being closed. This
// is purely an optimization since the listeners would all /eventually/ return
// when their timeouts were reached.
//
// It is each method's responsibility to check the 'closed' field first to
// ensure that the connection is not closed before doing anything. Note that
// some methods release and re-acquire mutexes during the course of execution.
// In that case, it is critical to re-check the 'closed' field, as it could have
// been modified while no locks were held!

const defaultOpTimeout = 10 * time.Second

// ErrClosed is the error returned when an already-closed connection is re-used.
var ErrClosed = fmt.Errorf("use of closed connection")

// ErrNotFound is not really an error, since timeouts race responses
var ErrNotFound = fmt.Errorf("connection removed")

// ErrTimeout is a timeout error
var ErrTimeout = fmt.Errorf("request timeout")

// Conn represents an open keyless connection.
type Conn struct {
	// In order to read, acquire readMtx; in order to write, acquire writeMtx
	conn net.Conn
	// In order to read, acquire mapMtx.RLock(); in order to write, acquire
	// mapMtx.Lock().
	listeners map[uint32]chan *result
	// In order to modify, acquire mapMtx.Lock().
	nextID uint32

	opTimeout time.Duration

	// To lock up the connection, always acquire in the following order to avoid
	// deadlock: writeMtx, mapMtx (don't acquire readMtx).
	readMtx, writeMtx sync.Mutex
	mapMtx            sync.Mutex

	// In order to read, acquire any mutex in any mode (read or write). In order
	// to modify, acquire all three.
	closed bool
}

type result struct {
	err error
	op  *protocol.Operation
}

// NewConnTimeout constructs a new Conn with the given operation timeout.
func NewConnTimeout(inner net.Conn, opTimeout time.Duration) *Conn {
	return &Conn{
		conn:      inner,
		listeners: make(map[uint32]chan *result),
		opTimeout: opTimeout,
	}
}

// NewConn constructs a new Conn with the default operation timeout of 10s.
func NewConn(inner net.Conn) *Conn {
	return NewConnTimeout(inner, defaultOpTimeout)
}

// Close closes the connection and causes all outstanding operations to fail.
func (c *Conn) Close() error {
	c.writeMtx.Lock()
	c.mapMtx.Lock()
	if c.closed {
		c.mapMtx.Unlock()
		c.writeMtx.Unlock()
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
	return err
}

// DoRead reads a packet from the connection and sends it to its intended
// recipient. On the client side, this should be called repeatedly. Each time it
// returns, the corresponding DoOperation call will stop blocking and return the
// response.
func (c *Conn) DoRead() error {
	// Acquire the read mutex until we're done reading.
	c.readMtx.Lock()
	pkt := new(protocol.Packet)
	_, err := pkt.ReadFrom(c.conn)
	c.readMtx.Unlock()
	if err != nil {
		return err
	}
	l, err := c.extractChannel(pkt.ID)
	if err != nil {
		// The timeout fired, our connection was removed.
		// Not a problem!
		if err == ErrNotFound {
			return nil
		}
		// Other errors close the whole connection
		return err
	}

	l <- &result{op: &pkt.Operation}
	return nil
}

func (c *Conn) extractChannel(id uint32) (chan *result, error) {
	c.mapMtx.Lock()
	defer c.mapMtx.Unlock()
	if c.closed {
		return nil, ErrClosed
	}
	ret, ok := c.listeners[id]
	delete(c.listeners, id)
	if !ok {
		return nil, ErrNotFound
	}
	return ret, nil
}

func (c *Conn) timeoutRequest(id uint32, timeout time.Duration) {
	<-time.After(timeout)
	place, err := c.extractChannel(id)
	if err != nil {
		return // the process finished successfully first
	}
	place <- &result{err: ErrTimeout}
}

// sendOp sends operation, returning a channel to wait for results
func (c *Conn) sendOp(ctx context.Context, op protocol.Operation) (chan *result, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "Conn.sendOp")
	defer span.Finish()
	tracing.SetOperationSpanTags(span, &op)
	// NOTE: It's very important that this channel be buffered so that if we
	// time out, but a reader finds this channel before we have a chance to delete
	// it from the map, the reader doesn't block forever sending us a value that
	// we will never receive.
	response := make(chan *result, 1)

	// Acquire the map mutex and only release it once we're done with the map.
	c.mapMtx.Lock()
	if c.closed {
		c.mapMtx.Unlock()
		return nil, ErrClosed
	}
	id := c.nextID
	c.nextID++
	if _, ok := c.listeners[id]; ok {
		c.mapMtx.Unlock()
		c.Close()
		// TODO: If this becomes an issue in practice, we could consider randomly
		// generating IDs and spinning until we find an available one (the map
		// acts as a record of all IDs currently in use).
		return nil, fmt.Errorf("could not allocate new packet ID: packet IDs wrapped around - this indicates a very fast client or a very slow server")
	}
	c.listeners[id] = response
	c.mapMtx.Unlock()

	pkt := protocol.NewPacket(id, op)

	// Acquire the write mutex and only release it once we're done writing.
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
		return nil, fmt.Errorf("could not set write deadline: %w", err)
	}
	_, err = pkt.WriteTo(c.conn)
	c.writeMtx.Unlock()
	if err != nil {
		return nil, fmt.Errorf("could not write to connection: %w", err)
	}
	// Take into account how long we've already been waiting since the beginning
	// of writing to the connection (which could have taken a while if the
	// connection was backed up).
	left := end.Sub(time.Now())
	go c.timeoutRequest(id, left)
	return response, nil

}

// DoOperation executes an entire keyless operation, returning its result.
func (c *Conn) DoOperation(ctx context.Context, op protocol.Operation) (*protocol.Operation, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "Conn.DoOperation")
	defer span.Finish()
	tracing.SetOperationSpanTags(span, &op)
	response, err := c.sendOp(ctx, op)
	if err != nil {
		span.SetTag("error", err)
		return nil, fmt.Errorf("DoOperation: %w", err)
	}
	res := <-response
	if res == nil {
		return nil, ErrClosed
	}
	if res.err != nil {
		span.SetTag("error", res.err)
		return nil, fmt.Errorf("DoOperation: resp error: %w", res.err)
	}
	return res.op, nil
}

// Ping sends a ping message over the connection and waits for a corresponding
// Pong response from the server.
func (c *Conn) Ping(ctx context.Context, data []byte) error {
	span, ctx := opentracing.StartSpanFromContext(ctx, "Conn.Ping")
	defer span.Finish()

	result, err := c.DoOperation(ctx, protocol.Operation{
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
