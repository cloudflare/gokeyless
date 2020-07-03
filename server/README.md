server
======

# Design

The architecture implemented in this package uses a worker pool model, with
each client being handled by its own pair of reader/writer goroutines, and
actual work being done by worker goroutines in a global worker pool.

It comprises a number of relatively independent components: the worker pool,
the client goroutines, the ECDSA precomputation, and the separation of ECDSA and RSA computations.

## Worker Pool

The worker pool is implemented in the `internal/pool` package by the `Pool`
type. Each worker pool runs a fixed number of worker goroutines that accept job
requests, perform the job, and process the responses.

A pool is served by a single channel on which jobs are submitted. Worker
goroutines simply loop reading jobs off this channel, executing the jobs, and
processing the result of those jobs.

A job is defined in the `Job` type:

```go
// A Job represents a unit of work to be done by a worker in the pool.
type Job struct { ... }

// NewJob creates a new Job. The job will be provided as the input to a worker's
// Do method, and once the Do method returns, its return value will be passed as
// the argument to commit.
func NewJob(job interface{}, commit func(result interface{})) Job
```

Each worker goroutine is given its own `Worker` object, which is capable of
executing jobs:

```go
// A Worker is capable of executing jobs.
type Worker interface {
	// Do performs the given job and returns the result.
	Do(job interface{}) (result interface{})
}
```

In the server, all requests from clients are submitted to a worker pool for execution.

## Clients

Each client is handled by a pair of goroutines. The logic is encapsulated in the `internal/worker` package's `Client` type and `SpawnClient` function.

In order to maximize throughput and minimize latency, reading and writing are handled in separate goroutines. One goroutine's job is to read requests off of the network connection from the client and submit them to the worker pool. The other goroutine's job is to receive the result of these operations from the worker pool, and to write the result to the network connection.

Each client maintains its own channel for receiving responses from the worker pool - the `commit` function that it uses for submitted jobs simply writes the job's result to that channel, and the writer goroutine loops reading from this channel.

## Clients and Pools

Putting it all together, we get an architecture that looks roughly like this:

![Architecture Diagram](http://i.imgur.com/HG8Mu5o.png)

## ECDSA Precomputation

ECDSA Signing can be broken down into two steps: First, some random values are generated for use in signing. Second, these values are used along with the inputs (the private key and the message to be signing) to compute the signature.

There are two notable facts about this arrangement. First, computing the random values can happen independently of both the private key and the message. Second, the computation of the random values represents the vast majority of the computational cost of computing an ECDSA signature. Consider, for example, these benchmarks from the `internal/ecdsa` package:

```text
# Time to compute various signatures given
# a pre-computed set of random values
BenchmarkSignECDSASHA224-4    500000        3012 ns/op
BenchmarkSignECDSASHA256-4    500000        2945 ns/op
BenchmarkSignECDSASHA384-4    500000        3270 ns/op
BenchmarkSignECDSASHA512-4    300000        3892 ns/op

# Time to generate random values
BenchmarkGenRandECDSASHA224-4  50000       30933 ns/op
BenchmarkGenRandECDSASHA256-4  50000       32737 ns/op
BenchmarkGenRandECDSASHA384-4    300     4961200 ns/op
BenchmarkGenRandECDSASHA512-4    200     8822477 ns/op
```

Thus, we have opted to split these two operations, and compute random values ahead of time. Note that one set of random values is still used for each signing operation, so the total computational cost to compute a particular number of signatures is unchanged - we don't gain anything in the way of bandwidth. However, in practice, most Keyless servers are far from bandwidth constrained, and even if they were, bandwidth constraints can be addressed by horizontal scaling.

Instead, this approach allows us to significantly reduce latency. We store a large (at the time of writing, 2^20 entries) buffer of sets of pre-computed random values, and keep a background goroutine that is constantly ensuring that the buffer is full. When a request comes in, a set of random values is retrieved from the buffer and used for computing the signature (if the buffer is empty, a new set is computed on the fly). Thus, so long as a supply of buffered sets of random values is maintained, the cost of computing each set of random values can be completely removed from the latency of serving a signing request.

Precomputation of random values is handled by a `BackgroundPool` - see the `internal/worker` package for documentation.

## ECDSA and RSA

RSA signatures are orders of magnitude more expensive to compute than ECDSA signatures, and do not benefit from the same ability to precompute random values. Thus, RSA signing operations will always be high-latency when compared with ECDSA signing operations.

In order to isolate ECDSA signing requests from the latency effects of RSA signing operations, we handle the two types of operations in separate worker pools. This way, even if the worker pool for RSA operations is completely saturated, there are always worker goroutines available to service ECDSA signing requests.

This design may add a small amount of latency to RSA signing requests, but it is very small compared to the cost of the RSA signing itself. On the other hand, we gain the ability to keep ECDSA signing requests very fast. Without this design, ECDSA signing requests would sometimes experience latency orders of magnitude larger than necessary due to pending RSA signing operations. Additionally, RSA is being phased out in certificates on the internet, so we expect this design to become more and more reasonable over time.
