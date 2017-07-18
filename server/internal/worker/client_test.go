package worker

import (
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
	requests  chan uint8
	responses chan struct{}
	closed    uint32
	pool      *Pool
}

func newDummyClient(pool *Pool) *dummyClient {
	return &dummyClient{
		requests:  make(chan uint8),
		responses: make(chan struct{}),
		pool:      pool,
	}
}

func (d *dummyClient) sendJob() {
	// Instead of having a complicated mechanism for not sending when the client
	// has been destroyed, just do this hack to catch the panic resulting from
	// sending on a closed channel.
	defer func() { recover() }()
	d.requests <- 1
}

func (d *dummyClient) receiveResponse() { <-d.responses }

func (d *dummyClient) GetJob() (job interface{}, pool *Pool, ok bool) {
	val := <-d.requests
	if val == 0 {
		return nil, nil, false
	}
	return 0, d.pool, true
}

func (d *dummyClient) SubmitResult(result interface{}) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	d.responses <- struct{}{}
	return true
}

func (d *dummyClient) IsAlive() bool { return atomic.LoadUint32(&d.closed) == 0 }

func (d *dummyClient) Destroy() {
	// Destroy can be called multiple times, and after the first time, the calls
	// to close will panic because we're closing a closed channel.
	defer func() { recover() }()
	atomic.StoreUint32(&d.closed, 1)
	close(d.requests)
	close(d.responses)
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
	cli.sendJob()
	handle.Destroy()
}

// This test tests the backpressure mechanism, ensuring that the number of
// outstanding requests is capped, and that relieving backpressure allows the
// system to make progress.
func TestClientBlocks(t *testing.T) {
	cli, handle := newClientSetup()

	for i := 0; i < maxOutstandingRequests+2; i++ {
		cli.sendJob()
	}

	// The number of outstanding requests is now the maximum; this should block.
	var done uint32
	go func() { cli.sendJob(); atomic.StoreUint32(&done, 1) }()

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
		cli.sendJob()
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
		cli.sendJob()
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
