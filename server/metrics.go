package server

import (
	"net/http"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/prometheus/client_golang/prometheus"
)

type statistics struct {
	requestDuration prometheus.Summary
	requestsInvalid prometheus.Counter
	connFailures    prometheus.Counter
}

func newStatistics() *statistics {
	stats := &statistics{
		requestDuration: prometheus.NewSummary(prometheus.SummaryOpts{
			Name: "request_duration",
			Help: "Requests duration summary in seconds",
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
	prometheus.MustRegister(s.stats.requestDuration)
	prometheus.MustRegister(s.stats.requestsInvalid)
	prometheus.MustRegister(s.stats.connFailures)
}
