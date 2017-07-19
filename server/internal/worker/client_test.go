package worker

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

type dummyClient struct {
	pool              *Pool
	getter, submitter chan int
	closed            bool
	mtx               sync.RWMutex
}

func newDummyClient(pool *Pool) *dummyClient {
	return &dummyClient{
		pool:      pool,
		getter:    make(chan int),
		submitter: make(chan int),
	}
}

// Simulate a network client sending a request.
func (d *dummyClient) sendRequest() {
	d.mtx.RLock()
	if d.closed {
		d.mtx.RUnlock()
		panic("sendRequest on closed dummyClient")
	}

	d.getter <- 1
	d.mtx.RUnlock()
}

// Simulate a network client receiving a job response.
func (d *dummyClient) receiveResponse() {
	d.mtx.RLock()
	if d.closed {
		d.mtx.RUnlock()
		panic("receiveResponse on a closed dummyClient")
	}

	d.submitter <- 1
	d.mtx.RUnlock()
}

func (d *dummyClient) GetJob() (job interface{}, pool *Pool, ok bool) {
	val := <-d.getter
	return 0, d.pool, val == 1
}

func (d *dummyClient) SubmitResult(result interface{}) (ok bool) {
	val := <-d.submitter
	return val == 1
}

func (d *dummyClient) IsAlive() bool {
	d.mtx.RLock()
	closed := d.closed
	d.mtx.RUnlock()
	return !closed
}

func (d *dummyClient) Destroy() {
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

func newClientSetup() (cli *dummyClient, handle *ClientHandle) {
	pool := NewPool(&dummyWorker{})
	cli = newDummyClient(pool)
	return cli, SpawnClient(cli)
}

func TestClientBasic(t *testing.T) {
	cli, handle := newClientSetup()
	cli.sendRequest()
	handle.Destroy()
}

// This test tests the backpressure mechanism, ensuring that the number of
// outstanding requests is capped, and that relieving backpressure allows the
// system to make progress.
func TestClientBlocks(t *testing.T) {
	cli, handle := newClientSetup()

	for i := 0; i < maxOutstandingRequests+2; i++ {
		cli.sendRequest()
	}

	// The number of outstanding requests is now the maximum; this should block.
	var done uint32
	go func() { cli.sendRequest(); atomic.StoreUint32(&done, 1) }()

	// Give the job plenty of time to be submitted if it's not blocked
	time.Sleep(10 * time.Millisecond)
	if atomic.LoadUint32(&done) == 1 {
		t.Errorf("job spuriously submitted")
	}

	// Allow one value to be submitted, unblocking the send above
	cli.receiveResponse()

	// Give the job time to be submitted
	time.Sleep(time.Millisecond)
	if atomic.LoadUint32(&done) == 0 {
		t.Errorf("job not submitted")
	}

	cli.receiveResponse()
	handle.Destroy()
}

// This test tests that even when the submitter is blocking due to backpressure,
// the ClientHandle can still be destroyed.
func TestClientDestroyDuringBackpressure(t *testing.T) {
	cli, handle := newClientSetup()

	for i := 0; i < maxOutstandingRequests+2; i++ {
		cli.sendRequest()
	}

	// The number of outstanding requests is now the maximum, so the submitter
	// should be blocking. Give them a bit of time just in case.
	time.Sleep(time.Millisecond)

	cli.receiveResponse()
	handle.Destroy()
}

// This test tests that even when the getter is blocking on GetJob, destroying
// the ClientHandle still works.
func TestClientDestroyDuringGet(t *testing.T) {
	_, handle := newClientSetup()
	handle.Destroy()
}

// This test tests that even when the submitter is blocking on SubmitJob,
// destroying the ClientHandle still works.
func TestClientDestroyDuringSubmit(t *testing.T) {
	cli, handle := newClientSetup()

	for i := 0; i < maxOutstandingRequests+2; i++ {
		cli.sendRequest()
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
	cli, handle := newClientSetup()
	cli.Destroy()
	handle.Wait()
	handle.Destroy()
}
