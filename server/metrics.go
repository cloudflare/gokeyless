package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/protocol"
	"github.com/prometheus/client_golang/prometheus"
)

type statistics struct {
	requestExecDuration          prometheus.Histogram
	requestTotalDuration         prometheus.Histogram
	requestExecDurationByOpcode  *prometheus.HistogramVec
	requestTotalDurationByOpcode *prometheus.HistogramVec
	requests                     prometheus.Counter
	requestsInvalid              prometheus.Counter
	requestOpcodes               *prometheus.CounterVec
	keyLoadDuration              prometheus.Histogram
	connFailures                 prometheus.Counter
	queuedECDSARequests          prometheus.Gauge
	queuedOtherRequests          prometheus.Gauge
}

var (
	// 1 microsecond as a fraction of 1 second
	us = 1e-6
	// buckets starting at 1 microsecond and doubling until reaching a maximum of
	// ~8 seconds
	durationBuckets = prometheus.ExponentialBuckets(us, 2.0, 24)
)

func newStatistics() *statistics {
	return &statistics{
		requestExecDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "keyless_request_execution_duration",
			Help:    "Time to execute a request not including time in queues.",
			Buckets: durationBuckets,
		}),
		requestTotalDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "keyless_request_total_duration",
			Help:    "Total time to satisfy a request including time in queues.",
			Buckets: durationBuckets,
		}),
		requestExecDurationByOpcode: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "keyless_request_exec_duration_per_opcode",
			Help:    "Time to execute a request not including time in queues, broken down by opcode.",
			Buckets: durationBuckets,
			// rsa_primes is only used for RSA signatures
		}, []string{"opcode", "rsa_primes"}),
		requestTotalDurationByOpcode: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "keyless_request_total_duration_per_opcode",
			Help:    "Total time to satisfy a request including time in queues, broken down by opcode.",
			Buckets: durationBuckets,
		}, []string{"opcode"}),
		requests: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "keyless_requests",
			Help: "Total number of requests.",
		}),
		requestsInvalid: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "keyless_requests_invalid",
			Help: "Number of invalid requests.",
		}),
		requestOpcodes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "keyless_request_opcodes",
			Help: "Number of requests received with various opcodes.",
		}, []string{"opcode"}),
		keyLoadDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "keyless_key_load_duration",
			Help:    "Time to load a requested key.",
			Buckets: durationBuckets,
		}),
		connFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "keyless_failed_connection",
			Help: "Number of connection/transport failure, in tls handshake and etc.",
		}),
		queuedECDSARequests: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "keyless_queued_ecdsa_requests",
			Help: "Number of queued ECDSA signing requests waiting to be executed.",
		}),
		queuedOtherRequests: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "keyless_queued_other_requests",
			Help: "Number of queued non-ECDSA requests waiting to be executed.",
		}),
	}
}

// logInvalid increments the error count and updates the error percentage.
func (stats *statistics) logInvalid(opcode protocol.Op) {
	stats.requestsInvalid.Inc()
}

// logConnFailure increments the error count of connFailures.
func (stats *statistics) logConnFailure() {
	stats.connFailures.Inc()
}

func (stats *statistics) logKeyLoadDuration(loadBegin time.Time) {
	stats.keyLoadDuration.Observe(float64(time.Now().Sub(loadBegin)) / float64(time.Second))
}

// logRequestExecDuration logs the time taken to execute an operation (not
// including queueing). If the operation is an RSA operation, primes is the
// number of primes in the RSA private key; otherwise, it is ignored.
func (stats *statistics) logRequestExecDuration(opcode protocol.Op, primes int, requestBegin time.Time) {
	stats.requestExecDuration.Observe(float64(time.Now().Sub(requestBegin)) / float64(time.Second))
	primesStr := ""
	switch opcode {
	case protocol.OpRSADecrypt, protocol.OpRSASignMD5SHA1, protocol.OpRSASignSHA1,
		protocol.OpRSASignSHA224, protocol.OpRSASignSHA256, protocol.OpRSASignSHA384,
		protocol.OpRSASignSHA512, protocol.OpRSAPSSSignSHA256,
		protocol.OpRSAPSSSignSHA384, protocol.OpRSAPSSSignSHA512:
		primesStr = fmt.Sprint(primes)
	}
	stats.requestExecDurationByOpcode.WithLabelValues(opcode.String(), primesStr).
		Observe(float64(time.Now().Sub(requestBegin)) / float64(time.Second))
}

func (stats *statistics) logRequestTotalDuration(opcode protocol.Op, requestBegin time.Time) {
	stats.requestTotalDuration.Observe(float64(time.Now().Sub(requestBegin)) / float64(time.Second))
	stats.requestTotalDurationByOpcode.WithLabelValues(opcode.String()).
		Observe(float64(time.Now().Sub(requestBegin)) / float64(time.Second))
}

func (stats *statistics) logEnqueueECDSARequest() { stats.queuedECDSARequests.Inc() }
func (stats *statistics) logDeqeueECDSARequest()  { stats.queuedECDSARequests.Dec() }
func (stats *statistics) logEnqueueOtherRequest() { stats.queuedOtherRequests.Inc() }
func (stats *statistics) logDeqeueOtherRequest()  { stats.queuedOtherRequests.Dec() }

func (stats *statistics) logRequest(opcode protocol.Op) {
	stats.requests.Inc()
	stats.requestOpcodes.WithLabelValues(opcode.String()).Inc()
}

// MetricsListenAndServe serves Prometheus metrics at metricsAddr
func (s *Server) MetricsListenAndServe(metricsAddr string) error {
	if metricsAddr != "" {
		s.RegisterMetrics()
		http.Handle("/metrics", prometheus.Handler())

		log.Infof("Serving metrics endpoint at %s/metrics\n", metricsAddr)
		return http.ListenAndServe(metricsAddr, nil)
	}
	return nil
}

// RegisterMetrics registers server metrics with global prometheus handler
func (s *Server) RegisterMetrics() {
	prometheus.MustRegister(
		s.stats.requestExecDuration,
		s.stats.requestTotalDuration,
		s.stats.requestExecDurationByOpcode,
		s.stats.requestTotalDurationByOpcode,
		s.stats.requests,
		s.stats.requestsInvalid,
		s.stats.requestOpcodes,
		s.stats.keyLoadDuration,
		s.stats.connFailures,
		s.stats.queuedECDSARequests,
		s.stats.queuedOtherRequests,
	)
}
