package client

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/gokeyless/server/internal/worker"
)

func TestBlocker(t *testing.T) {
	b := newBlocker(1)
	if b.Do() {
		t.Fatalf("unexpected closed blocker")
	}
	b.Done()
	if b.Do() {
		t.Fatalf("unexpected closed blocker")
	}
	b.Close()
	if !b.Do() {
		t.Fatalf("unexpected open blocker")
	}
}

type dummyConn struct {
	pool              *worker.Pool
	getter, submitter chan int
	closed            bool
	mtx               sync.RWMutex
}

func newDummyConn(pool *worker.Pool) *dummyConn {
	return &dummyConn{
		pool:      pool,
		getter:    make(chan int),
		submitter: make(chan int),
	}
}

// Simulate a network client sending a request.
func (d *dummyConn) sendRequest() {
	d.mtx.RLock()
	if d.closed {
		d.mtx.RUnlock()
		panic("sendRequest on closed dummyClient")
	}

	d.getter <- 1
	d.mtx.RUnlock()
}

// Simulate a network client receiving a job response.
func (d *dummyConn) receiveResponse() {
	d.mtx.RLock()
	if d.closed {
		d.mtx.RUnlock()
		panic("receiveResponse on a closed dummyClient")
	}

	d.submitter <- 1
	d.mtx.RUnlock()
}

func (d *dummyConn) GetJob() (job interface{}, pool *worker.Pool, ok bool) {
	val := <-d.getter
	return 0, d.pool, val == 1
}

func (d *dummyConn) SubmitResult(result interface{}) (ok bool) {
	val := <-d.submitter
	return val == 1
}

func (d *dummyConn) IsAlive() bool {
	d.mtx.RLock()
	closed := d.closed
	d.mtx.RUnlock()
	return !closed
}

func (d *dummyConn) Destroy() {
	d.mtx.Lock()
	if d.closed {
		d.mtx.Unlock()
		return
	}
	d.closed = true
	close(d.getter)
	close(d.submitter)
	d.mtx.Unlock()
}

type dummyWorker struct{}

func (d *dummyWorker) Do(job interface{}) (result interface{}) { return job }

func newConnSetup() (conn *dummyConn, handle *ConnHandle) {
	pool := worker.NewPool(&dummyWorker{})
	conn = newDummyConn(pool)
	return conn, SpawnConn(conn)
}

func TestClientBasic(t *testing.T) {
	conn, handle := newConnSetup()
	conn.sendRequest()
	handle.Destroy()
}

// This test tests the backpressure mechanism, ensuring that the number of
// outstanding requests is capped, and that relieving backpressure allows the
// system to make progress.
func TestClientBlocks(t *testing.T) {
	conn, handle := newConnSetup()

	for i := 0; i < maxOutstandingRequests+2; i++ {
		conn.sendRequest()
	}

	// The number of outstanding requests is now the maximum; this should block.
	var done uint32
	go func() { conn.sendRequest(); atomic.StoreUint32(&done, 1) }()

	// Give the job plenty of time to be submitted if it's not blocked
	time.Sleep(10 * time.Millisecond)
	if atomic.LoadUint32(&done) == 1 {
		t.Errorf("job spuriously submitted")
	}

	// Allow one value to be submitted, unblocking the send above
	conn.receiveResponse()

	// Give the job time to be submitted
	time.Sleep(time.Millisecond)
	if atomic.LoadUint32(&done) == 0 {
		t.Errorf("job not submitted")
	}

	conn.receiveResponse()
	handle.Destroy()
}

// This test tests that even when the submitter is blocking due to backpressure,
// the ClientHandle can still be destroyed.
func TestClientDestroyDuringBackpressure(t *testing.T) {
	conn, handle := newConnSetup()

	for i := 0; i < maxOutstandingRequests+2; i++ {
		conn.sendRequest()
	}

	// The number of outstanding requests is now the maximum, so the submitter
	// should be blocking. Give them a bit of time just in case.
	time.Sleep(time.Millisecond)

	conn.receiveResponse()
	handle.Destroy()
}

// This test tests that even when the getter is blocking on GetJob, destroying
// the ClientHandle still works.
func TestClientDestroyDuringGet(t *testing.T) {
	_, handle := newConnSetup()
	handle.Destroy()
}

// This test tests that even when the submitter is blocking on SubmitJob,
// destroying the ClientHandle still works.
func TestClientDestroyDuringSubmit(t *testing.T) {
	conn, handle := newConnSetup()

	for i := 0; i < maxOutstandingRequests+2; i++ {
		conn.sendRequest()
	}

	// The number of outstanding requests is now the maximum, so the submitter
	// should be blocking. Give them a bit of time just in case.
	time.Sleep(time.Millisecond)

	handle.Destroy()
}

// This test tests that calling Destroy is safe even after the underlying client
// has already gone away. It also tests that Wait will return properly if the
// underlying client goes away.
func TestClientDestroyAfterQuit(t *testing.T) {
	conn, handle := newConnSetup()
	conn.Destroy()
	handle.Wait()
	handle.Destroy()
}
