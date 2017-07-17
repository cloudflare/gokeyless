`bench` Tool
============

The `bench` tool is used to benchmark a Keyless server. It is capable of measuring bandwidth or latency, and has a number of configuration options.

It works by creating a number of TLS connections to a Keyless server, with each connection served by its own worker goroutine (or, in the case of the bandwidth test, pair of worker goroutines). These workers submit jobs for some period of time until the test completes, and measures the latency or bandwidth of responses during that period.

## Latency

In the latency test, each worker submits a request and then waits for that request's response before submitting the next request. It measures the latency between submitting the request and receiving the response. It also pauses for some duration between iterations to simulate real-world traffic, in which requests do not arrive at a very high rate.

The output of the latency test is a histogram describing the distributions of latencies - e.g., how many requests took between 0 and 1 microseconds, how many took between 1 and 2, etc. The histogram is configurable using the various `-histogram-XXX` flags.

## Bandwidth

In the bandwidth test, each connection has two goroutines - a reader and a writer. The writer sends requests as fast as it can, and the reader reads responses as fast as it can. No synchronization is performed between the two, and responses are simply received in whatever order they arrive and are immediately discarded. The bandwidth is measured as the number of responses received over the duration of the test.

The output of the bandwidth test is the number of responses received across all workers and the rate at which responses were received (responses per second).

# Options

Here we document a number of particularly important options; there are more options besides these that are either unimportant or whose behavior is self-evident. To see the full list of options, run `bench -h`.

* `-op`: The operation to request. Keyless supports a number of operations: cryptographic signing and decryption, unsealing, etc. All requests in the test will be for this operation.
* `-workers`: The number of workers (and hence the number of connections) to use. If the test is a latency test, then the number of worker goroutines is equal to this number. If the test is a bandwidth test, then the number of worker goroutines is twice this number since each connection gets two worker goroutines.
* `-pause`: For latency tests, the duration to wait between tests. Real-world Keyless servers receive requests at a relatively low rate, with long periods of downtime between any two requests on a given connection. This pause is used to simulate that behavior.
