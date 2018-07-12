package server

import (
	"net/http"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/protocol"
	"github.com/prometheus/client_golang/prometheus"
)

type statistics struct {
	requestExecDuration  *prometheus.HistogramVec
	requestTotalDuration *prometheus.HistogramVec
	requests             *prometheus.CounterVec
	requestsInvalid      *prometheus.CounterVec
	keyLoadDuration      prometheus.Histogram
	connFailures         prometheus.Counter
	queuedECDSARequests  prometheus.Gauge
	queuedOtherRequests  prometheus.Gauge
}

var (
	// buckets starting at 100 microseconds and doubling until reaching a
	// maximum of ~3.3 seconds
	durationBuckets = prometheus.ExponentialBuckets(1e-4, 2.0, 15)
)

func newStatistics() *statistics {
	return &statistics{
		requestExecDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "keyless_request_exec_duration_per_opcode",
			Help:    "Time to execute a request not including time in queues, broken down by type and error code.",
			Buckets: durationBuckets,
		}, []string{"type", "error"}),
		requestTotalDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "keyless_request_total_duration_per_opcode",
			Help:    "Total time to satisfy a request including time in queues, broken down by type and error code.",
			Buckets: durationBuckets,
		}, []string{"type", "error"}),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "keyless_requests",
			Help: "Total number of requests by opcode.",
		}, []string{"opcode"}),
		requestsInvalid: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "keyless_requests_invalid",
			Help: "Number of invalid requests by opcode.",
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

func (stats *statistics) logRequest(opcode protocol.Op) {
	stats.requests.WithLabelValues(opcode.String()).Inc()
}

func (stats *statistics) logInvalid(opcode protocol.Op) {
	stats.requestsInvalid.WithLabelValues(opcode.String()).Inc()
}

func (stats *statistics) logConnFailure() {
	stats.connFailures.Inc()
}

func (stats *statistics) logKeyLoadDuration(loadBegin time.Time) {
	stats.keyLoadDuration.Observe(time.Since(loadBegin).Seconds())
}

// logRequestExecDuration logs the time taken to execute an operation (not
// including queueing).
func (stats *statistics) logRequestExecDuration(opcode protocol.Op, requestBegin time.Time, err protocol.Error) {
	stats.requestExecDuration.WithLabelValues(opcode.Type(), err.String()).Observe(time.Since(requestBegin).Seconds())
}

func (stats *statistics) logRequestTotalDuration(opcode protocol.Op, requestBegin time.Time, err protocol.Error) {
	stats.requestTotalDuration.WithLabelValues(opcode.Type(), err.String()).Observe(time.Since(requestBegin).Seconds())
}

func (stats *statistics) logEnqueueECDSARequest() { stats.queuedECDSARequests.Inc() }
func (stats *statistics) logDeqeueECDSARequest()  { stats.queuedECDSARequests.Dec() }
func (stats *statistics) logEnqueueOtherRequest() { stats.queuedOtherRequests.Inc() }
func (stats *statistics) logDeqeueOtherRequest()  { stats.queuedOtherRequests.Dec() }

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
		s.stats.requests,
		s.stats.requestsInvalid,
		s.stats.keyLoadDuration,
		s.stats.connFailures,
		s.stats.queuedECDSARequests,
		s.stats.queuedOtherRequests,
	)
}
