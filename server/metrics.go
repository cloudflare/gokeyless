package server

import (
	"net/http"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/prometheus/client_golang/prometheus"
)

type statistics struct {
	requests        prometheus.Summary
	requestsInvalid prometheus.Counter
	connFailures    prometheus.Counter
}

func newStatistics() *statistics {
	stats := &statistics{
		requests: prometheus.NewSummary(prometheus.SummaryOpts{
			Name: "requests",
			Help: "Curent latency in responding to requests.",
		}),
		requestsInvalid: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "requests_invalid",
			Help: "Number of invalid requests.",
		}),
		connFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "failed_connection",
			Help: "Number of connection/transport failure, in tls handshake and etc..",
		}),
	}
	return stats
}

// logInvalid increments the error count and updates the error percentage.
func (stats *statistics) logInvalid(requestBegin time.Time) {
	stats.requestsInvalid.Inc()
	stats.logRequest(requestBegin)
}

// logConnFailure increments the error count of connFailures.
func (stats *statistics) logConnFailure() {
	stats.connFailures.Inc()
}

// logRequest increments the request count and updates the error percentage.
func (stats *statistics) logRequest(requestBegin time.Time) {
	stats.requests.Observe(float64(time.Now().Sub(requestBegin)))
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
	prometheus.MustRegister(s.stats.requests)
	prometheus.MustRegister(s.stats.requestsInvalid)
	prometheus.MustRegister(s.stats.connFailures)
}
