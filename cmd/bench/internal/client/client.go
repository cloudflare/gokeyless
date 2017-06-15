package client

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// A LatencyBucket represents one bucket in a latency histogram, recording the
// number of requests which took in the range [From, Until].
type LatencyBucket struct {
	From, Until time.Duration
	Count       uint64
}

// PrintHistogram prints a histogram of the given buckets to stdout. The buckets
// are assumed to be non-overlapping intervals sorted in ascending order.
func PrintHistogram(buckets []LatencyBucket) {
	// To save screen space - especially because RunLatencyClients always returns
	// a histogram whose largest bucket goes to the maximum time.Duration value -
	// represent time.Duration(math.MaxInt64) as "-" instead of formatting the
	// actual time.
	durString := func(d time.Duration) string {
		if d == time.Duration(math.MaxInt64) {
			return "-"
		}
		return fmt.Sprint(d)
	}

	max := uint64(0)
	firstNonzero := -1 // first bucket with Count > 0
	lastNonzero := 0   // last bucket with Count > 0
	maxFromLen := 0    // maximum length of string-formatted From field
	maxUntilLen := 0   // maximum length of string-formatted Until field
	for i, b := range buckets {
		if b.Count > max {
			max = b.Count
		}
		if b.Count > 0 {
			if firstNonzero == -1 {
				firstNonzero = i
			}
			lastNonzero = i

			// Only count the length of the durations we're going to print - thus, do
			// this logic inside this if block. The input could have 0-count buckets
			// in between other non-zero-count buckets, but as long as the buckets are
			// ascending in their from/until durations, the later buckets will always
			// have equal- or greater-length duration strings than the current one, so
			// skipping intermediate zero-count buckets is acceptable.
			fromlen, untillen := len(durString(b.From)), len(durString(b.Until))
			if fromlen > maxFromLen {
				maxFromLen = fromlen
			}
			if untillen > maxUntilLen {
				maxUntilLen = untillen
			}
		}
	}

	maxCountLen := len(fmt.Sprint(max))

	fmtstr := fmt.Sprintf("[%%%vv, %%%vv) %%%vv | %%v\n", maxFromLen, maxUntilLen, maxCountLen)
	fmax := float64(max)
	for _, b := range buckets[firstNonzero : lastNonzero+1] {
		perc := float64(b.Count) / fmax
		height := int(perc * 70)
		fmt.Printf(fmtstr, durString(b.From), durString(b.Until), b.Count, strings.Repeat("=", height))
	}
}

// A BandwidthClient is a client used for bandwidth measurements. It must be
// safe for Dispatch and Complete to be called concurrently from different
// goroutines, although neither method needs to be safe for other concurrent
// calls to itself. In other words, at most one call to each of the two methods
// will be in progress at any given time.
type BandwidthClient interface {
	// Dispatch dispatches a new request, but does not wait for it to complete.
	Dispatch()

	// Complete waits for the next request to complete. It must wait for whatever
	// request is the first to complete rather than waiting for a particular
	// request.
	Complete()
}

// RunBandwidthClients runs the provided BandwidthClients for the duration d.
// For each client, two goroutines are spawned. One loops calling Dispatch, and
// the other loops calling Complete. The total number of calls to Complete
// (across all clients) is returned.
//
// Note that since only calls to Complete are recorded, it is possible (in fact,
// quite likely) that there will be outstanding requests (created by Dispatch)
// when the test quits. This means that the bandwidth estimate is a conservative
// one. It also means that a very small value for d may skew results by making
// it so that a large portion of the time is spent waiting for the first request
// to return (effectively measuring request latency rather than steady state
// bandwidth).
func RunBandwidthClients(d time.Duration, clients ...BandwidthClient) uint64 {
	if len(clients) == 0 {
		panic("no clients")
	}

	// the marker will be atomically set to 1 when it's time for the goroutines to
	// quit
	var marker uint32
	stop := func() bool { return atomic.LoadUint32(&marker) == 1 }

	var counts = make([]uint64, len(clients))

	var barrier, wg sync.WaitGroup
	barrier.Add(1)
	wg.Add(len(clients))
	for i, c := range clients {
		go func(i int, c BandwidthClient) {
			barrier.Wait()
			counts[i] = runBandwidthUntil(c, stop)
			wg.Done()
		}(i, c)
	}

	barrier.Done()
	time.Sleep(d)
	atomic.StoreUint32(&marker, 1)
	wg.Wait()

	sum := uint64(0)
	for _, count := range counts {
		sum += count
	}
	return sum
}

// runBandwidthUntil spawns two goroutines, with one repeatedly calling
// c.Dispatch and the other repeatedly calling c.Complete. This continues until
// stop returns true, at which point the goroutines quit and return the total
// number of successfully completed requests. Some requests may be left
// outstanding.
func runBandwidthUntil(c BandwidthClient, stop func() bool) uint64 {
	// We don't do any synchronization between the two goroutines, but the
	// dispatch goroutine will eventually find stop() return false and will quit.
	go func() {
		for !stop() {
			c.Dispatch()
		}
	}()

	var count uint64
	for !stop() {
		c.Complete()
		count++
	}
	return count
}

// A LatencyClient is a client used for latency measurements.
type LatencyClient interface {
	// Do executes a request and returns the duration.
	Do() time.Duration
}

// FuncLatencyClient is a function that implements the LatencyClient interface.
type FuncLatencyClient func() time.Duration

// Do invokes f.
func (f FuncLatencyClient) Do() time.Duration { return f() }

var _ LatencyClient = FuncLatencyClient(nil)

// RunLatencyClients runs the provided LatencyClients - each in its own
// goroutine - for the duration d. It collects a histogram of the latencies
// experienced by calls to Do. The lowest bucket will be from 0 to min, followed
// by buckets whose width is given by step until max, followed by a bucket from
// max to the maximum time.Duration.
func RunLatencyClients(d time.Duration, min, max, step time.Duration, clients ...LatencyClient) []LatencyBucket {
	if len(clients) == 0 {
		panic("no clients")
	}

	// the marker will be atomically set to 1 when it's time for the goroutines to
	// quit
	var marker uint32
	stop := func() bool { return atomic.LoadUint32(&marker) == 1 }

	var histograms = make([][]LatencyBucket, len(clients))

	var barrier, wg sync.WaitGroup
	barrier.Add(1)
	wg.Add(len(clients))
	for i, c := range clients {
		go func(i int, c LatencyClient) {
			barrier.Wait()
			histograms[i] = runLatencyUntil(c, min, max, step, stop)
			wg.Done()
		}(i, c)
	}

	barrier.Done()
	time.Sleep(d)
	atomic.StoreUint32(&marker, 1)
	wg.Wait()

	// since we got these histograms from runUntil, we know that they all have the
	// same set and order of ranges, so we can trivially add them together to get
	// the final answer. We arbitrarily pick histograms[0] to accumulate into.
	buckets := histograms[0]
	for _, bkts := range histograms[1:] {
		for i, bkt := range bkts {
			buckets[i].Count += bkt.Count
		}
	}
	return buckets
}

func runLatencyUntil(c LatencyClient, bottom, top, skip time.Duration, stop func() bool) []LatencyBucket {
	diff := top - bottom
	nbuckets := int(diff / skip)
	latencyCounts := make([]uint64, nbuckets+2)
	for !stop() {
		dur := c.Do()
		if dur < bottom {
			latencyCounts[0]++
		} else if dur > top {
			latencyCounts[nbuckets-1]++
		} else {
			bucketIdx := int((dur - bottom) / skip)
			latencyCounts[bucketIdx]++
		}
	}

	buckets := make([]LatencyBucket, nbuckets+2)
	buckets[0].Until = bottom - 1
	buckets[0].Count = latencyCounts[0]
	buckets[nbuckets-1].From = top
	buckets[nbuckets-1].Until = time.Duration(math.MaxInt64)
	buckets[nbuckets-1].Count = latencyCounts[nbuckets-1]
	for i := 0; i < nbuckets-2; i++ {
		buckets[i+1].From = bottom + (time.Duration(i) * skip)
		buckets[i+1].Until = bottom + ((time.Duration(i) + 1) * skip) - 1
		buckets[i+1].Count = latencyCounts[i+1]
	}
	return buckets
}
