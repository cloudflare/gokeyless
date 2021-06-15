package server

import (
	"fmt"
	"sync"
	"time"

	"github.com/cloudflare/gokeyless/protocol"
	"github.com/cloudflare/gokeyless/server/internal/worker"
)

// WorkerPoolType represents the different available worker pool types.
type WorkerPoolType string

// Enumerate the available pool types.
const (
	PoolRSA    WorkerPoolType = "rsa"
	PoolECDSA                 = "ecdsa"
	PoolOther                 = "other"
	PoolRemote                = "remote"
)

// A WorkerPoolSelector returns the appropriate WorkerPoolType based on the
// request.
type WorkerPoolSelector func(pkt *protocol.Packet) WorkerPoolType

type workerPool struct {
	RSA     *worker.Pool
	ECDSA   *worker.Pool
	Other   *worker.Pool
	Remote  *worker.Pool
	Limited *worker.Pool

	selector WorkerPoolSelector
	utilCh   chan struct{}
	utilWg   sync.WaitGroup
}

func newWorkerPool(s *Server) (*workerPool, error) {
	// This is mostly so we don't divide by zero below, but will also prevent
	// inoperable configurations.
	if s.config.rsaWorkers <= 0 ||
		s.config.ecdsaWorkers <= 0 ||
		s.config.otherWorkers <= 0 ||
		s.config.remoteWorkers <= 0 {
		return nil, fmt.Errorf("non-zero number of RSA, ECDSA, Other and Remote  workers is required")
	}

	var ecdsas []worker.Worker
	var rsas []worker.Worker
	var others []worker.Worker
	var remotes []worker.Worker
	var limiteds []worker.Worker
	for i := 0; i < s.config.rsaWorkers; i++ {
		rsas = append(rsas, newKeylessWorker(s, fmt.Sprintf("rsa-%v", i)))
	}
	for i := 0; i < s.config.ecdsaWorkers; i++ {
		ecdsas = append(ecdsas, newKeylessWorker(s, fmt.Sprintf("ecdsa-%v", i)))
	}
	for i := 0; i < s.config.remoteWorkers; i++ {
		remotes = append(remotes, newKeylessWorker(s, fmt.Sprintf("remote-%v", i)))
	}
	for i := 0; i < s.config.otherWorkers; i++ {
		others = append(others, newKeylessWorker(s, fmt.Sprintf("other-%v", i)))
	}
	for i := 0; i < s.config.limitedWorkers; i++ {
		limiteds = append(limiteds, newLimitedWorker(s, fmt.Sprintf("limited-%v", i)))
	}
	wp := &workerPool{
		RSA:      worker.NewPool(rsas...),
		ECDSA:    worker.NewPool(ecdsas...),
		Remote:   worker.NewPool(remotes...),
		Other:    worker.NewPool(others...),
		Limited:  worker.NewPool(limiteds...),
		selector: s.config.poolSelector,
		utilCh:   make(chan struct{}),
	}

	for _, label := range []string{"rsa", "ecdsa", "other", "limited", "remote"} {
		serverUtilization.WithLabelValues(label)
	}
	wp.utilWg.Add(1)
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		for {
			select {
			case <-ticker.C:
				serverUtilization.WithLabelValues("rsa").Set(float64(wp.RSA.Busy()) / float64(s.config.rsaWorkers))
				serverUtilization.WithLabelValues("ecdsa").Set(float64(wp.ECDSA.Busy()) / float64(s.config.ecdsaWorkers))
				serverUtilization.WithLabelValues("other").Set(float64(wp.Other.Busy()) / float64(s.config.otherWorkers))
				serverUtilization.WithLabelValues("remote").Set(float64(wp.Remote.Busy()) / float64(s.config.remoteWorkers))
				if s.config.limitedWorkers > 0 {
					serverUtilization.WithLabelValues("limited").Set(float64(wp.Limited.Busy()) / float64(s.config.limitedWorkers))
				}

			case <-wp.utilCh:
				ticker.Stop()
				wp.utilWg.Done()
				return
			}
		}
	}()

	return wp, nil
}

func (wp *workerPool) Destroy() {
	// Destroy the pools
	wp.Other.Destroy()
	wp.ECDSA.Destroy()
	wp.RSA.Destroy()
	wp.Remote.Destroy()
	wp.Limited.Destroy()
	// Stop publishing utilization info.
	close(wp.utilCh)
	wp.utilWg.Wait()
}
