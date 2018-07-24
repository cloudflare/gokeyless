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
	// used by the LogConnErr method
	logErr sync.Once
	s      *Server

	closed uint32 // set to 1 when the conn is closed.

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
		// TODO: Is it possible for the client closing this half of the connection
		// to cause SetReadDeadline to return io.EOF? If so, we may want to do the
		// same logic as the other error handling block in this function.
		c.LogConnErr(err)
		c.conn.Close()
		atomic.StoreUint32(&c.closed, 1)
		return nil, nil, false
	}

	pkt := new(protocol.Packet)
	_, err = pkt.ReadFrom(c.conn)
	if err != nil {
		if err == io.EOF {
			// We can't rule out the possibility that the client just closed the
			// writing half of their connection (the reading half of ours), but still
			// wants to receive responses. Thus, we don't kill the connection.
			//
			// We also don't call c.Log because the writer goroutine could, in the
			// future, encounter an error that we legitimately want logged. Even if no
			// "real" error is encountered, when the other half of the connection is
			// closed, the writer goroutine will encounter EOF, and will log it, so
			// even if the connection is closed correctly, it will still get logged.
			log.Debugf("connection %v: reading half closed by client %s", c.name, c.stats)
		} else {
			c.LogConnErr(err)
			c.conn.Close()
		}
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
	c.LogConnErr(nil)
	c.conn.Close()
	atomic.StoreUint32(&c.closed, 1)
}

// Log an error with the connection (reading, writing, setting a deadline, etc).
// Any error logged here is a fatal one that will cause us to terminate the
// connection and clean up the client.
func (c *conn) LogConnErr(err error) {
	// Use a sync.Once so that only the first goroutine to encounter an error gets
	// to log it. This avoids the circumstance where a goroutine encounters an
	// error, logs it, and then closes the network connection, which causes the
	// other goroutine to also encounter an error (due to the closed connection)
	// and spuriously log it.
	//
	// We also use this to allow Destroy to block the reader or writer from
	// logging anything at all by calling Log(nil).
	c.logErr.Do(func() {
		if err == nil {
			// Destroy was called, and it called Log to ensure that the errors
			// encountered by the reader and writer due to interacting with a closed
			// connection are not logged.
			log.Debugf("connection %v: server closing connection %s", c.name, c.stats)
			return
		} else if err == io.EOF {
			log.Debugf("connection %v: closed by client %s", c.name, c.stats)
		} else {
			c.s.stats.logConnFailure()
			log.Errorf("connection %v: encountered error: %v %s", c.name, err, c.stats)
		}
	})
}
