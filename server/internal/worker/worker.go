package worker

import (
	"context"
	"sync"
	"sync/atomic"
)

// A Job represents a unit of work to be done by a worker in the pool.
type Job struct {
	// job == nil is used as a sentinel value to instruct workers to quit
	job    interface{}
	commit func(result interface{})
}

// NewJob creates a new Job. job will be provided as the input to a worker's Do
// method, and once the Do method returns, its return value will be passed as
// the argument to commit.
func NewJob(job interface{}, commit func(result interface{})) Job {
	if job == nil {
		panic("nil job")
	}
	return Job{job: job, commit: commit}
}

// A Worker is capable of executing jobs.
type Worker interface {
	// Do performs the given job and returns the result.
	Do(job interface{}) (result interface{})
}

// A Pool is a handle on a pool of worker goroutines that can execute jobs.
type Pool struct {
	busy    int64
	jobs    chan Job
	workers int
	wg      sync.WaitGroup
}

// NewPool constructs a new Pool from the given workers. Each worker is run in
// its own goroutine. The workers wait jobs to be submitted and execute those
// jobs as they come in.
func NewPool(workers ...Worker) *Pool {
	p := &Pool{
		jobs:    make(chan Job, 1024*1024),
		workers: len(workers),
	}

	p.wg.Add(len(workers))
	for _, w := range workers {
		go func(w Worker) {
			p.worker(w)
			p.wg.Done()
		}(w)
	}
	return p
}

// SubmitJob submits a new job to the pool. It may block if the queue of pending
// jobs is full. If p has already been destroyed (p.Destroy()), the behavior of
// SubmitJob is undefined.
func (p *Pool) SubmitJob(job Job) {
	p.jobs <- job
}

// Destroy destroys the pool. Any currently-executing calls to Do complete, and
// then the worker goroutines quit. Destroy only returns after all worker
// goroutines have quit. If p has already been destroyed, the behavior of
// Destroy is undefined.
func (p *Pool) Destroy() {
	for i := 0; i < p.workers; i++ {
		// Send the sentinal value (with the 'job' field as nil) indicating to quit;
		// send one for each worker goroutine.
		p.jobs <- Job{}
	}
	p.wg.Wait()
}

func (p *Pool) worker(w Worker) {
	for {
		job := <-p.jobs
		if job.job == nil {
			return
		}

		atomic.AddInt64(&p.busy, 1)
		result := w.Do(job.job)
		job.commit(result)
		atomic.AddInt64(&p.busy, -1)
	}
}

// Busy returns the number of workers that are currently busy.
func (p *Pool) Busy() int {
	return int(atomic.LoadInt64(&p.busy))
}

// A BackgroundWorker performs a unit of background work when Do is called.
type BackgroundWorker interface {
	// Do performs a unit of background work.
	Do(ctx context.Context)
}

// A BackgroundPool is a handle on a pool of worker goroutines that execute
// background jobs. Unlike a Pool, a BackgroundPool does not accept job requests
// from elsewhere in the system, but instead does pre-set work on its own.
type BackgroundPool struct {
	ctx context.Context
	cf  context.CancelFunc

	wg sync.WaitGroup
}

// NewBackgroundPool constructs a new BackgroundPool from the given workers.
// Each worker is run in its own goroutine. The workers simply spin, calling Do
// until the pool is destroyed.
func NewBackgroundPool(workers ...BackgroundWorker) *BackgroundPool {
	ctx, cf := context.WithCancel(context.Background())
	p := &BackgroundPool{ctx: ctx, cf: cf}

	p.wg.Add(len(workers))
	for _, i := range workers {
		go func(w BackgroundWorker) {
			p.worker(w)
			p.wg.Done()
		}(i)
	}
	return p
}

// Destroy destroys the pool. Any currently-executing calls to Do complete or
// safely terminate early, and then the worker goroutines quit. Destroy only
// returns after all worker goroutines have quit. If p has already been
// destroyed, the behavior of Destroy is undefined.
func (p *BackgroundPool) Destroy() {
	p.cf()
	p.wg.Wait()
}

func (p *BackgroundPool) worker(w BackgroundWorker) {
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			w.Do(p.ctx)
		}
	}
}
