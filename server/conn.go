package server

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/protocol"
	"github.com/cloudflare/gokeyless/server/internal/worker"
)

// conn implements the client.Conn interface. One is created to handle each
// connection from clients over the network. See the documentation in the client
// package for details.
type conn struct {
	conn net.Conn
	// name used to identify this client in logs
	name                 string
	timeout              time.Duration
	ecdsaPool, otherPool *worker.Pool
	s                    *Server

	closed        uint32 // set to 1 when the conn is closed
	serverClosing uint32 // set to 1 when the conn is being closed by the server (i.e. not an error)

	stats *connStats
}

type connEvent struct {
	time   time.Time
	id     uint32
	opcode protocol.Op
}

type connStats struct {
	spawnTime time.Time
	reads     int
	writes    int
	lastRead  connEvent
	lastWrite connEvent

	lock sync.Mutex
}

func (s *connStats) String() string {
	s.lock.Lock()
	str := fmt.Sprintf(
		"spawnTime=%s read=%d lastReadId=%d lastReadTime=%s written=%d lastWriteId=%d lastWriteTime=%s",
		s.spawnTime.Format(time.RFC3339),
		s.reads,
		s.lastRead.id,
		s.lastRead.time.Format(time.RFC3339),
		s.writes,
		s.lastWrite.id,
		s.lastWrite.time.Format(time.RFC3339),
	)
	s.lock.Unlock()
	return str
}

func newConn(s *Server, name string, c net.Conn, timeout time.Duration, ecdsa, other *worker.Pool) *conn {
	return &conn{
		conn:      c,
		name:      name,
		timeout:   timeout,
		ecdsaPool: ecdsa,
		otherPool: other,
		s:         s,
		closed:    0,
		stats: &connStats{
			spawnTime: time.Now(),
		},
	}
}

func (c *conn) GetJob() (job interface{}, pool *worker.Pool, ok bool) {
	err := c.conn.SetReadDeadline(time.Now().Add(c.timeout))
	if err != nil {
		c.LogConnErr(err)
		c.conn.Close()
		atomic.StoreUint32(&c.closed, 1)
		return nil, nil, false
	}

	pkt := new(protocol.Packet)
	_, err = pkt.ReadFrom(c.conn)
	if err != nil {
		c.LogConnErr(err)
		c.conn.Close()
		atomic.StoreUint32(&c.closed, 1)
		return nil, nil, false
	}

	c.s.stats.logRequest(pkt.Opcode)
	req := request{
		pkt:      pkt,
		reqBegin: time.Now(),
		connName: c.name,
	}

	c.stats.lock.Lock()
	c.stats.reads++
	c.stats.lastRead.id = pkt.ID
	c.stats.lastRead.time = req.reqBegin
	c.stats.lastRead.opcode = pkt.Opcode
	c.stats.lock.Unlock()

	switch pkt.Operation.Opcode {
	case protocol.OpECDSASignMD5SHA1, protocol.OpECDSASignSHA1,
		protocol.OpECDSASignSHA224, protocol.OpECDSASignSHA256,
		protocol.OpECDSASignSHA384, protocol.OpECDSASignSHA512:
		c.s.stats.logEnqueueECDSARequest()
		return req, c.ecdsaPool, true
	default:
		c.s.stats.logEnqueueOtherRequest()
		return req, c.otherPool, true
	}
}

func (c *conn) SubmitResult(result interface{}) bool {
	resp := result.(response)
	pkt := protocol.Packet{
		Header: protocol.Header{
			MajorVers: 0x01,
			MinorVers: 0x00,
			Length:    resp.op.Bytes(),
			ID:        resp.id,
		},
		Operation: resp.op,
	}

	buf, err := pkt.MarshalBinary()
	if err != nil {
		// According to MarshalBinary's documentation, it will never return a
		// non-nil error.
		panic(fmt.Sprintf("unexpected internal error: %v", err))
	}

	_, err = c.conn.Write(buf)
	if err != nil {
		c.LogConnErr(err)
		c.conn.Close()
		atomic.StoreUint32(&c.closed, 1)
		return false
	}

	c.s.stats.logRequestTotalDuration(resp.reqOpcode, resp.reqBegin, resp.err)

	c.stats.lock.Lock()
	c.stats.writes++
	c.stats.lastWrite.id = pkt.ID
	c.stats.lastWrite.time = time.Now()
	c.stats.lastWrite.opcode = resp.reqOpcode
	c.stats.lock.Unlock()

	return true
}

func (c *conn) IsAlive() bool {
	return atomic.LoadUint32(&c.closed) == 0
}

func (c *conn) Destroy() {
	atomic.StoreUint32(&c.serverClosing, 1)
	c.LogConnErr(nil)
	c.conn.Close()
	atomic.StoreUint32(&c.closed, 1)
}

// Log an error with the connection (reading, writing, setting a deadline, etc).
// Any error logged here is a fatal one that will cause us to terminate the
// connection and clean up the client.
func (c *conn) LogConnErr(err error) {
	// When the server is proactively closing connections, this function will be
	// called twice: once with a nil error, and then once again with a non-nil
	// error when the reader goroutine reads from the closed connection. This
	// check ensures we don't log an expected error.
	if err != nil && atomic.LoadUint32(&c.serverClosing) == 1 {
		return
	}

	if err == nil { // We're destroying the connection
		log.Debugf("connection %v: server closing connection %s", c.name, c.stats)
	} else if err == io.EOF {
		log.Debugf("connection %v: closed by client %s", c.name, c.stats)
	} else {
		c.s.stats.logConnFailure()
		log.Errorf("connection %v: encountered error: %v %s", c.name, err, c.stats)
	}
}
