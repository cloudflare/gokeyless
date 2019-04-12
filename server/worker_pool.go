package server

import (
	"crypto/elliptic"
	"fmt"
	"sync"
	"time"

	buf_ecdsa "github.com/cloudflare/gokeyless/server/internal/ecdsa"
	"github.com/cloudflare/gokeyless/server/internal/worker"
)

type workerPool struct {
	ECDSA   *worker.Pool
	Other   *worker.Pool
	Limited *worker.Pool

	bg     *worker.BackgroundPool
	utilCh chan struct{}
	utilWg sync.WaitGroup
}

func newWorkerPool(s *Server) *workerPool {
	var others []worker.Worker
	var ecdsas []worker.Worker
	var limiteds []worker.Worker
	var background []worker.BackgroundWorker
	rbuf := buf_ecdsa.NewSyncRandBuffer(randBufferLen, elliptic.P256())
	for i := 0; i < s.config.otherWorkers; i++ {
		others = append(others, newOtherWorker(s, fmt.Sprintf("other-%v", i)))
	}
	for i := 0; i < s.config.ecdsaWorkers; i++ {
		ecdsas = append(ecdsas, newECDSAWorker(s, rbuf, fmt.Sprintf("ecdsa-%v", i)))
	}
	for i := 0; i < s.config.limitedWorkers; i++ {
		limiteds = append(limiteds, newLimitedWorker(s, fmt.Sprintf("limited-%v", i)))
	}
	for i := 0; i < s.config.bgWorkers; i++ {
		background = append(background, newRandGenWorker(rbuf))
	}

	wp := &workerPool{
		ECDSA:   worker.NewPool(ecdsas...),
		Other:   worker.NewPool(others...),
		Limited: worker.NewPool(limiteds...),
		bg:      worker.NewBackgroundPool(background...),
		utilCh:  make(chan struct{}),
	}

	if util := s.config.utilization; util != nil {
		wp.utilWg.Add(1)
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			for {
				select {
				case <-ticker.C:
					util(
						float64(wp.Other.Busy())/float64(s.config.otherWorkers),
						float64(wp.ECDSA.Busy())/float64(s.config.ecdsaWorkers),
					)

				case <-wp.utilCh:
					ticker.Stop()
					wp.utilWg.Done()
					return
				}
			}
		}()
	}

	return wp
}

func (wp *workerPool) Destroy() {
	// Destroy the pools
	wp.bg.Destroy()
	wp.Other.Destroy()
	wp.ECDSA.Destroy()
	// Stop publishing utilization info.
	close(wp.utilCh)
	wp.utilWg.Wait()
}
