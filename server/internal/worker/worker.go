package worker

import (
	"sync"
	"sync/atomic"
)

// A Job represents a unit of work to be done by a worker in the pool.
type Job struct {
	// job == nil is used as a sentinal value to instruct workers to quit
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

// An Idler performs a unit of background work when Idle is called.
type Idler interface {
	// Idle performs a unit of background work.
	Idle()
}

// A Worker is capable of executing jobs.
type Worker interface {
	// Do performs the given job and returns the result.
	Do(job interface{}) (result interface{})
}

// A Pool is a handle on a pool of worker goroutines that can execute jobs or
// idle work.
type Pool struct {
	jobs    chan Job
	workers int // number of workers (not including idlers)
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

// Destroy destroys the pool. Any currently-executing calls to Idle or Do
// complete, and then the worker goroutines quit. Destroy only returns after all
// worker goroutines have quit. If p has already been destroyed, the behavior of
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
		result := w.Do(job.job)
		job.commit(result)
	}
}

// An IdlePool is a handle on a pool of worker goroutines that can execute idle
// work.
type IdlePool struct {
	quit uint32 // used to signal to the workers to quit
	wg   sync.WaitGroup
}

// NewIdlePool constructs a new IdlePool from the given idlers. Each idler is
// run in its own goroutine. The idlers simply spin, calling Idle until the pool
// is destroyed.
func NewIdlePool(idlers ...Idler) *IdlePool {
	p := &IdlePool{}

	p.wg.Add(len(idlers))
	for _, i := range idlers {
		go func(i Idler) {
			p.worker(i)
			p.wg.Done()
		}(i)
	}
	return p
}

// Destroy destroys the pool. Any currently-executing calls to Idle complete,
// and then the worker goroutines quit. Destroy only returns after all worker
// goroutines have quit. If p has already been destroyed, the behavior of
// Destroy is undefined.
func (p *IdlePool) Destroy() {
	// Instruct the idle goroutines to quit. They will observe this change on the
	// next loop iteration.
	atomic.StoreUint32(&p.quit, 1)
	p.wg.Wait()
}

func (p *IdlePool) worker(i Idler) {
	for {
		if atomic.LoadUint32(&p.quit) == 1 {
			return
		}
		i.Idle()
	}
}
