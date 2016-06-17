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
	}
	prometheus.MustRegister(stats.requests)
	prometheus.MustRegister(stats.requestsInvalid)

	return stats
}

// logInvalid increments the error count and updates the error percentage.
func (stats *statistics) logInvalid(requestBegin time.Time) {
	stats.requestsInvalid.Inc()
	stats.logRequest(requestBegin)
}

// logRequest increments the request count and updates the error percentage.
func (stats *statistics) logRequest(requestBegin time.Time) {
	stats.requests.Observe(float64(time.Now().Sub(requestBegin)))
}

func (s *Server) MetricsListenAndServe() error {
	if s.MetricsAddr != "" {
		http.Handle("/metrics", prometheus.Handler())

		log.Infof("Serving metrics endpoint at %s/metrics\n", s.MetricsAddr)
		return http.ListenAndServe(s.MetricsAddr, nil)
	}
	return nil
}
