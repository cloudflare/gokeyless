package worker

import (
	"sync"
	"sync/atomic"
	"time"
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

// A Client is a server-side handle on a connection to a client. It is capable
// of reading job requests from the client, writing responses to the client, and
// shutting down the connection.
//
// Since Clients can be backed by TCP connections, it is acceptable for GetJob
// to return false (indicating that there are no jobs to be done - in the case
// of a TCP connection, caused by a half-close of the connection) while
// SubmitResult continues to return true (because writing to the connection is
// still allowed).
type Client interface {
	// GetJob returns the next job to perform, or ok = false if there are no more
	// jobs to do. If it returns a job, it also returns the pool to which that job
	// should be submitted.
	GetJob() (job interface{}, pool *Pool, ok bool)

	// SubmitResult submits the result of a previously-requested job. If the
	// result cannot be submitted, it returns false. This implies that the client
	// is completely closed and no results can ever be submitted in the future.
	SubmitResult(result interface{}) (ok bool)

	// IsAlive returns whether or not the client is still alive (if no more
	// jobs can be gotten via GetJob, but submitting is still enabled, the client
	// is considered alive). So long as the client is alive, it is acceptable for
	// IsAlive to block. Once the client has died, it must not block. Thus, it is
	// legal to implement IsAlive by blocking until the client is dead and then
	// returning false.
	IsAlive() bool

	// Destroy destructs the client's connection. After a call to Destroy, all
	// pending calls to GetJob and SubmitResult should immediately return false,
	// and any future calls to those methods should also immediately return false.
	//
	// It must be safe to call Destroy multiple times; all calls after the first
	// are no-ops.
	Destroy()
}

// A ClientHandle is a handle on a pair of reader/writer goroutines that are
// processing requests from a client.
type ClientHandle struct {
	client    Client
	wg        sync.WaitGroup
	responses chan interface{}
	blocker   *blocker
	destroyed uint32 // atomically set to 1 when destroyed
}

// SpawnClient spawns a pair of goroutines to handle requests from the client.
// One goroutine reads jobs from the client and submits them a worker pool,
// while the other waits of the results of these jobs and writes them to the
// client.
func SpawnClient(client Client) *ClientHandle {
	c := &ClientHandle{
		client: client,
		// responses needs to have an extra slot for the sentinal value sent by
		// Destroy
		responses: make(chan interface{}, maxOutstandingRequests+2),
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
	go func() {
		for {
			time.Sleep(time.Second)
			// NOTE: This call may simply block until c.client is dead, but that's
			// fine.
			if !c.client.IsAlive() {
				c.destroy()
				return
			}
		}
	}()

	return c
}

// Destroy destructs the client. It calls Destroy on the Client that this handle
// was originally constructed with, and shuts down both background goroutines.
// It only returns once both goroutines have quit.
//
// If Destroy is called on a ClientHandle which has already been destroyed, the
// behavior is undefined.
func (c *ClientHandle) Destroy() {
	wasDestroyed := !atomic.CompareAndSwapUint32(&c.destroyed, 0, 1)
	if wasDestroyed {
		// This isn't technically necessary - we document that behavior in this case
		// is undefined - but it's nice and makes it less likely that bugs will slip
		// by unnoticed.
		panic("destroy already-destroyed ClientHandle")
	}
	c.destroy()
	c.wg.Wait()
}

func (c *ClientHandle) destroy() {
	// Make any call (including currently outstanding calls) to GetJob or
	// SubmitResult immediately return false. This will signal to getter or setter
	// to return.
	c.client.Destroy()
	// Make any call (including currently outstanding calls) to Do immediately
	// return with a value indicating that the blocker has been closed. This will
	// signal to getter to return if it's blocking on c.blocker.Do().
	c.blocker.Close()
	// The submitter might be blocked reading from the responses channel, in which
	// case c.client.Destroy() will not be sufficient to instruct it to return. In
	// case that's true, we send this sentinal value to tell it to return. This
	// type is not exported, so nobody outside this package can construct an
	// instance of it. Note that it's very important that responses has one more
	// slot than the number of possible outstanding requests so that there's
	// guaranteed to be room for this sentinal value.
	//
	// NOTE: It would NOT be safe to simply close the channel instead because we
	// don't know whether there are outstanding jobs being done by workers; if
	// there are, then closing this channel would cause them to panic when they
	// tried to write their responses.
	c.responses <- done{}
}

// Wait blocks until both background goroutines have quit. This can happen
// either because of a call to c.Destroy or because the underlying client was
// closed or encountered an error.
func (c *ClientHandle) Wait() { c.wg.Wait() }

func (c *ClientHandle) getter() {
	commit := func(resp interface{}) { c.responses <- resp }
	for {
		job, pool, ok := c.client.GetJob()
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
		pool.SubmitJob(NewJob(job, commit))
	}
}

func (c *ClientHandle) submitter() {
	for {
		resp := <-c.responses
		if (resp == done{}) {
			return
		}

		// Indicate that we've read another response off the channel, so there's
		// room for one more outstanding request to be submitted without risk of
		// causing a worker goroutine to block.
		c.blocker.Done()
		ok := c.client.SubmitResult(resp)
		if !ok {
			return
		}
	}
}

// An arbitrary type guaranteed not to be instantiated by anyone outside this
// package.
type done struct{}

// A blocker is an object that keeps track of a number of outstanding requests,
// and blocks if that number would exceed some maximum.
type blocker struct {
	// requestsLeft holds one token (uint8(1)) for every request that can be
	// submitted before the requests need to block. The channel is closed when
	// this blocker is closed, causing all future reads to immediately return 0.
	requestsLeft chan uint8
}

func newBlocker(max int) *blocker {
	b := &blocker{requestsLeft: make(chan uint8, max)}
	for i := 0; i < max; i++ {
		b.requestsLeft <- 1
	}
	return b
}

// Do increments the number of outstanding requests by one. If the new number of
// outstanding requests would exceed the maximum, Do blocks until it is safe to
// increment the number of outstanding requests without exceeding the maximum.
func (b *blocker) Do() (closed bool) {
	val := <-b.requestsLeft
	// We only ever send 1 on the channel, so 0 implies that the channel was
	// closed (reads from a closed channel return the 0 value).
	return val == 0
}

// Done decrements the number of outstanding requests by one.
func (b *blocker) Done() {
	// if b.requestsLeft is closed, the send will panic, so we recover from it
	// (NOTE: for some reason 'defer recover()' alone doesn't work, but this does)
	defer func() { recover() }()
	b.requestsLeft <- 1
}

// Close closes b. Any current or future calls to Do will immediately return
// true. It is safe to call Close multiple times.
func (b *blocker) Close() {
	// Close can be called multiple times, and after the first time, the call to
	// close will panic because we're closing a closed channel.
	defer func() { recover() }()
	close(b.requestsLeft)
}
