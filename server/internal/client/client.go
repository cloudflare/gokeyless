package client

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/gokeyless/server/internal/worker"
)

// Design
//
// This file implements functionality for reading requests from a client,
// submitting those requests as jobs to one or more worker pools, and writing
// responses back to the client.
//
// In addition to providing an ergonomic interface, this implementation aims to
// address keep some of the subtle logic involved self-contained so that it's
// easy to reason about and easy to verify its correctness. In particular, it is
// easy to accidentally introduce deadlock bugs, livelock bugs, or DoS
// vulnerabilities.
//
// The primary DoS vector that we are concerned about in this implementation is
// induced deadlock. In particular, a malicious client could submit jobs
// continuously while not reading the responses to those jobs, and cause the
// system to deadlock. Before we describe our solution to this problem, we
// describe two potential solutions that are incorrect. The ways in which they
// are incorrect will motivate our design.
//
// Solution 1: Bounded Channels
//
// Two goroutines are spawned - one for reading requests from the connection,
// and the other for writing responses. A bounded channel is created with
// capacity N that is used by worker goroutines to send responses to the writer
// goroutine. Job submission goes through the normal pool mechanism (the
// SubmitJob method, which writes to a bounded pool-global channel of jobs).
//
// Consider what happens with this design if a malicious client continually
// sends jobs, but does not read any responses. Eventually, the amount of
// buffered data in the server-to-client half of the TCP stream on both the
// client and the server will max out, causing future write calls on the server
// to block. This will cause the writer goroutine to block, which will mean that
// nobody is reading responses off of the response channel. Eventually, the
// results of jobs submitted by the client will completely fill up the response
// channel, and sends on that channel will block. Eventually, every worker
// goroutine will be blocked sending on the response channel, and the system
// will be completely deadlocked, unable to process any jobs.
//
// Solution 2: Unbounded Channels
//
// The exact same architecture is used as in Solution 1, except that the
// response channel is unbounded, so sends will never block.
//
// If a malicious client were to execute the same attack, the workers would be
// able to continue sending responses to the channel and thus continue to
// process new jobs - they would never get stuck blocking on sending to the
// response channel. However, this would happen at the cost of the amount of
// data buffered in the response channel growing without bound. Instead of
// deadlocking the system, the attack would cause the system to eventually run
// out of memory.
//
// The Real Solution
//
// Given the issues with the two discussed solutions, the real solution we use
// employs a mechanism for introducing backpressure that flows directly from the
// outbound half of connection to the inbound half. The mechanism is simple -
// we introduce a 'blocker' type whose job is to count the number of outstanding
// requests. If that number exceeds some configured maximum, any method call to
// increase the number of outstanding requests will block until the number of
// outstanding requests falls below the maximum again.
//
// This ensures that backpressure caused by a client not reading from their
// network connection translates directly into backpressure on them sending on
// their connection. If the maximum is reached, then the reading goroutine will
// block until the number of outstanding requests falls below the maximum again,
// and for that time, it will not be reading any new requests off the
// connection.
//
// The response channel is configured to have a capacity equal to the maximum
// number of outstanding requests plus two. This ensures that regardless of how
// slowly the client reads responses off the connection, there will always be
// room in the channel for the responses to be written, and so no worker
// goroutine will ever need to block; the extra two slots are for a sentinal
// value which is used by destroy to signal to the submitter goroutine that it
// should quit - it's important that sending that value never block either (and
// destroy can be called twice - once by Destroy and once by the liveness
// checker goroutine).

// A note on liveness checking:
//
// If the server itself does not opt to destroy a connection, there is a chance
// that even if the client disconnects or there is a network error, the
// background goroutines will not detect and return. This is especially a
// problem because we allow the getter goroutine to quit without informing the
// sender (since it is valid for a client to close only the half of the TCP
// connection they are using to send requests, and still expect responses to
// come back on the other half of the connection).
//
// Consider the following scenario: A client connects, and sends no requests.
// Then, it closes the connection. The getter goroutine interprets this as a
// close of only one side of the connection, and returns. The submitter
// goroutine is blocked reading responses from the response channel, but of
// course no responses will ever come.
//
// To deal with this problem, for every connection, we spawn a background
// goroutine that infrequently (currently once per second) polls the client to
// see if it's still alive. If not, it destroys the whole setup (just like if a
// user called Destroy). Since Destroy can only be called once by a user, it
// must be safe for the underlying destroy procedure to be invoked twice - once
// by the user, and once by this monitor goroutine.

const (
	maxOutstandingRequests = 1024
)

// A note on using Destroy:
//
// We need some mechanism for the code to decide that it wants to kill an
// existing client (primarily when the user requests that the server shut down).
// One approach is to have each ClientHandle have a global marker of some kind
// that both the getter and the submitter check once per loop to see if they
// should return. However, this mechanism requires that network reads and writes
// time out quickly so that the loop is executed frequently. This in turn
// requires intermediate partial reads or writes to be buffered and then
// completed on the next loop. For writing, this isn't so bad - it's just a
// matter of keeping track of how many bytes were written already. For reading,
// it's somewhat more complicated, requiring keeping partial parse state.
//
// Instead, we sidestep this issue by allowing network reads and writes to block
// as long as they want to, and instead using the Destroy method, which closes
// the network connection. Closing a network connection causes all existing
// pending reads and writes to immediately return, so this allows us to simply
// call Destroy and know that outstanding calls to GetJob or SubmitResult will
// immediately return.

// A Conn is a server-side handle on a connection to a client. It is capable
// of reading job requests from the client, writing responses to the client, and
// shutting down the connection.
//
// Since Conns can be backed by TCP connections, it is acceptable for GetJob to
// return false (indicating that there are no jobs to be done - in the case of a
// TCP connection, caused by a half-close of the connection) while SubmitResult
// continues to return true (because writing to the connection is still
// allowed).
type Conn interface {
	// GetJob returns the next job to perform, or ok = false if there are no more
	// jobs to do. If it returns a job, it also returns the pool to which that job
	// should be submitted.
	GetJob() (job interface{}, pool *worker.Pool, ok bool)

	// SubmitResult submits the result of a previously-requested job. If the
	// result cannot be submitted, it returns false. This implies that the client
	// is completely closed and no results can ever be submitted in the future.
	SubmitResult(result interface{}) (ok bool)

	// IsAlive returns whether or not the client is still alive (if no more
	// jobs can be gotten via GetJob, but submitting is still enabled, the client
	// is considered alive). Once it returns false, it may never return true
	// again.
	//
	// It must be safe to call IsAlive so long as the Client object exists.
	IsAlive() bool

	// Destroy destructs the client's connection. After a call to Destroy, all
	// pending calls to GetJob and SubmitResult should immediately return false,
	// and any future calls to those methods should also immediately return false.
	//
	// It must be safe to call Destroy multiple times; all calls after the first
	// are no-ops.
	Destroy()
}

// A ConnHandle is a handle on a pair of reader/writer goroutines that are
// processing requests from a client.
type ConnHandle struct {
	conn      Conn
	wg        sync.WaitGroup
	responses chan interface{}
	done      chan struct{}
	blocker   *blocker
	destroyed uint32 // atomically set to 1 when destroyed
}

// SpawnConn spawns a pair of goroutines to handle requests from the client. One
// goroutine reads jobs from the client and submits them a worker pool, while
// the other waits of the results of these jobs and writes them to the client.
func SpawnConn(conn Conn) *ConnHandle {
	c := &ConnHandle{
		conn:      conn,
		responses: make(chan interface{}, maxOutstandingRequests),
		done:      make(chan struct{}),
		blocker:   newBlocker(maxOutstandingRequests),
	}
	c.wg.Add(2)

	go func() {
		c.getter()
		c.wg.Done()
	}()
	go func() {
		c.submitter()
		c.wg.Done()
	}()

	// NOTE: The background liveness checking goroutine doesn't participate in the
	// WaitGroup because we don't care about it - it doesn't affect anything if
	// it's still alive.
	go func() {
		for {
			time.Sleep(time.Second)
			if atomic.LoadUint32(&c.destroyed) == 1 {
				return
			}
			if !c.conn.IsAlive() {
				c.destroy()
				return
			}
		}
	}()

	return c
}

// Destroy destructs the conn. It calls Destroy on the Conn that this handle was
// originally constructed with, and shuts down both background goroutines. It
// only returns once both goroutines have quit.
//
// If Destroy is called on a ConnHandle which has already been destroyed, the
// behavior is undefined.
func (c *ConnHandle) Destroy() {
	c.destroy()
	c.wg.Wait()
}

func (c *ConnHandle) destroy() {
	// This function may be called both by the health checker and explicitly, so
	// we ensure we only execute it once.
	wasDestroyed := !atomic.CompareAndSwapUint32(&c.destroyed, 0, 1)
	if wasDestroyed {
		return
	}

	// Make any call (including currently outstanding calls) to GetJob or
	// SubmitResult immediately return false. This will signal to getter or setter
	// to return.
	c.conn.Destroy()
	// Make any call (including currently outstanding calls) to Do immediately
	// return with a value indicating that the blocker has been closed. This will
	// signal to getter to return if it's blocking on c.blocker.Do().
	c.blocker.Close()
	// The submitter might be blocked reading from the responses channel, in which
	// case c.client.Destroy() will not be sufficient to instruct it to return. In
	// case that's true, we close the done channel to signal it to exit.
	close(c.done)
}

// Wait blocks until both background goroutines have quit. This can happen
// either because of a call to c.Destroy or because the underlying client was
// closed or encountered an error.
func (c *ConnHandle) Wait() { c.wg.Wait() }

func (c *ConnHandle) getter() {
	commit := func(resp interface{}) { c.responses <- resp }
	for {
		job, pool, ok := c.conn.GetJob()
		if !ok {
			return
		}

		// Indicate that we're about to submit another job. If there wouldn't be
		// room in the response channel for this job's response (thus causing a
		// worker to block), this call will block to prevent us from locking up the
		// system. This call will unblock once there is room or the blocker is
		// closed (indicating it's time for us to quit).
		closed := c.blocker.Do()
		if closed {
			return
		}
		pool.SubmitJob(worker.NewJob(job, commit))
	}
}

func (c *ConnHandle) submitter() {
	for {
		var resp interface{}
		select {
		case <-c.done:
			return
		case resp = <-c.responses:
		}

		// Indicate that we've read another response off the channel, so there's
		// room for one more outstanding request to be submitted without risk of
		// causing a worker goroutine to block.
		c.blocker.Done()
		ok := c.conn.SubmitResult(resp)
		if !ok {
			return
		}
	}
}

// A blocker is an object that keeps track of a number of outstanding requests,
// and blocks if that number would exceed some maximum.
type blocker struct {
	// initialized to the maximum number of outstanding requests; if it is -1,
	// implies that somebody is blocked in a call to Do
	requestsLeft int
	// used by Do to block if requestsLeft reaches -1
	wg     sync.WaitGroup
	closed bool
	mtx    sync.Mutex
}

func newBlocker(max int) *blocker {
	return &blocker{requestsLeft: max}
}

// Do increments the number of outstanding requests by one. If the new number of
// outstanding requests would exceed the maximum, Do blocks until it is safe to
// increment the number of outstanding requests without exceeding the maximum.
//
// It is not safe to call Do concurrently with other calls to Do. It is safe to
// call Do concurrently with calls to Done or Close.
func (b *blocker) Do() (closed bool) {
	b.mtx.Lock()
	if b.closed {
		b.mtx.Unlock()
		return true
	}
	b.requestsLeft--
	if b.requestsLeft >= 0 {
		b.mtx.Unlock()
		return false
	}

	b.wg.Add(1)
	b.mtx.Unlock()
	b.wg.Wait()
	b.mtx.Lock()
	closed = b.closed
	b.mtx.Unlock()
	return closed
}

// Done decrements the number of outstanding requests by one.
func (b *blocker) Done() {
	b.mtx.Lock()
	if b.closed {
		b.mtx.Unlock()
		return
	}
	b.requestsLeft++
	if b.requestsLeft == 0 {
		b.wg.Done()
	}
	b.mtx.Unlock()
}

// Close closes b. Any current or future calls to Do will immediately return
// true. It is safe to call Close multiple times.
func (b *blocker) Close() {
	b.mtx.Lock()
	if b.closed {
		b.mtx.Unlock()
		return
	}
	b.closed = true
	if b.requestsLeft < 0 {
		b.wg.Done()
	}
	b.mtx.Unlock()
}
