package server

import (
	"net/http"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/prometheus/client_golang/prometheus"
)

type statistics struct {
	requestDuration     prometheus.Summary
	requestsInvalid     prometheus.Counter
	connFailures        prometheus.Counter
	queuedECDSARequests prometheus.Gauge
	queuedOtherRequests prometheus.Gauge
}

func newStatistics() *statistics {
	stats := &statistics{
		requestDuration: prometheus.NewSummary(prometheus.SummaryOpts{
			Name: "keyless_request_duration",
			Help: "Requests duration summary in seconds.",
		}),
		requestsInvalid: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "keyless_requests_invalid",
			Help: "Number of invalid requests.",
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
	return stats
}

// logInvalid increments the error count and updates the error percentage.
func (stats *statistics) logInvalid(requestBegin time.Time) {
	stats.requestsInvalid.Inc()
	stats.logRequestDuration(requestBegin)
}

// logConnFailure increments the error count of connFailures.
func (stats *statistics) logConnFailure() {
	stats.connFailures.Inc()
}

// logRequest increments the request count and updates the error percentage.
func (stats *statistics) logRequestDuration(requestBegin time.Time) {
	stats.requestDuration.Observe(float64(time.Now().Sub(requestBegin)) / float64(time.Second))
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
		s.stats.requestDuration,
		s.stats.requestsInvalid,
		s.stats.connFailures,
		s.stats.queuedECDSARequests,
		s.stats.queuedOtherRequests,
	)
}
