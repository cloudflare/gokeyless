package worker

import (
	"crypto/sha256"
	"runtime"
	"sync"
	"testing"
	"time"
)

var input = []byte("this is some stuff to hash")

func hashNRounds(n int, buf []byte) [sha256.Size]byte {
	hash := sha256.Sum256(buf)
	for i := 1; i < n; i++ {
		hash = sha256.Sum256(hash[:])
	}
	return hash
}

type funcWorker func(job interface{}) (result interface{})

func (f funcWorker) Do(job interface{}) (result interface{}) { return f(job) }

// benchmark operations which take a given number of rounds (more rounds means
// each operation will be proportionally more expensive), enqueued from the
// given number of producer/consumer pairs.
func benchPool(b *testing.B, rounds int, pcpairs int) {
	nworkers := runtime.NumCPU()
	var workers []Worker
	for i := 0; i < nworkers; i++ {
		workers = append(workers, funcWorker(func(job interface{}) interface{} {
			return hashNRounds(rounds, job.([]byte))
		}))
	}
	pool := NewPool(workers...)

	// Give the worker goroutines a change to spawn
	time.Sleep(100 * time.Millisecond)

	var barrier, wg sync.WaitGroup
	barrier.Add(1)
	wg.Add(2 * pcpairs)

	for i := 0; i < pcpairs; i++ {
		res := make(chan [sha256.Size]byte, 1024*1024)
		commit := func(result interface{}) { res <- result.([sha256.Size]byte) }

		// producer
		go func(commit func(result interface{})) {
			barrier.Wait()
			for i := 0; i < b.N*nworkers/pcpairs; i++ {
				job := NewJob(input, commit)
				pool.SubmitJob(job)
			}
			wg.Done()
		}(commit)

		//consumer
		go func(res chan [sha256.Size]byte) {
			barrier.Wait()
			for i := 0; i < b.N*nworkers/pcpairs; i++ {
				<-res
			}
			wg.Done()
		}(res)
	}

	b.ResetTimer()
	barrier.Done()
	wg.Wait()
	b.StopTimer()

	pool.Destroy()
}

func benchSingle(b *testing.B, rounds int) {
	for i := 0; i < b.N; i++ {
		hashNRounds(rounds, input)
	}
}

func BenchmarkPool001Round1Pair(b *testing.B)   { benchPool(b, 1, 1) }
func BenchmarkPool001Round2Pairs(b *testing.B)  { benchPool(b, 1, 2) }
func BenchmarkPool002Rounds1Pair(b *testing.B)  { benchPool(b, 2, 1) }
func BenchmarkPool002Rounds2Pairs(b *testing.B) { benchPool(b, 2, 2) }
func BenchmarkPool004Rounds1Pair(b *testing.B)  { benchPool(b, 4, 1) }
func BenchmarkPool004Rounds2Pairs(b *testing.B) { benchPool(b, 4, 2) }
func BenchmarkPool008Rounds1Pair(b *testing.B)  { benchPool(b, 8, 1) }
func BenchmarkPool008Rounds2Pairs(b *testing.B) { benchPool(b, 8, 2) }
func BenchmarkPool016Rounds1Pair(b *testing.B)  { benchPool(b, 16, 1) }
func BenchmarkPool016Rounds2Pairs(b *testing.B) { benchPool(b, 16, 2) }
func BenchmarkPool032Rounds1Pair(b *testing.B)  { benchPool(b, 32, 1) }
func BenchmarkPool032Rounds2Pairs(b *testing.B) { benchPool(b, 32, 2) }
func BenchmarkPool064Rounds1Pair(b *testing.B)  { benchPool(b, 64, 1) }
func BenchmarkPool064Rounds2Pairs(b *testing.B) { benchPool(b, 64, 2) }
func BenchmarkPool128Rounds1Pair(b *testing.B)  { benchPool(b, 128, 1) }
func BenchmarkPool128Rounds2Pairs(b *testing.B) { benchPool(b, 128, 2) }
func BenchmarkPool256Rounds1Pair(b *testing.B)  { benchPool(b, 256, 1) }
func BenchmarkPool256Rounds2Pairs(b *testing.B) { benchPool(b, 256, 2) }

func BenchmarkSingle001Round(b *testing.B)  { benchSingle(b, 1) }
func BenchmarkSingle002Rounds(b *testing.B) { benchSingle(b, 2) }
func BenchmarkSingle004Rounds(b *testing.B) { benchSingle(b, 4) }
func BenchmarkSingle008Rounds(b *testing.B) { benchSingle(b, 8) }
func BenchmarkSingle016Rounds(b *testing.B) { benchSingle(b, 16) }
func BenchmarkSingle032Rounds(b *testing.B) { benchSingle(b, 32) }
func BenchmarkSingle064Rounds(b *testing.B) { benchSingle(b, 64) }
func BenchmarkSingle128Rounds(b *testing.B) { benchSingle(b, 128) }
func BenchmarkSingle256Rounds(b *testing.B) { benchSingle(b, 256) }
