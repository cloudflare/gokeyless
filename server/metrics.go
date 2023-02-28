package server

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	"github.com/cloudflare/gokeyless/protocol"
)

var (
	// buckets starting at 100 microseconds and doubling until reaching a
	// maximum of ~3.3 seconds
	durationBuckets = prometheus.ExponentialBuckets(1e-4, 2.0, 15)

	requestExecDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "keyless_request_exec_duration_per_opcode",
		Help:    "Time to execute a request not including time in queues, broken down by type and error code.",
		Buckets: durationBuckets,
	}, []string{"type", "error"})
	requestTotalDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "keyless_request_total_duration_per_opcode",
		Help:    "Total time to satisfy a request including time in queues, broken down by type and error code.",
		Buckets: durationBuckets,
	}, []string{"type", "error"})
	requests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "keyless_requests",
		Help: "Total number of requests by opcode.",
	}, []string{"opcode"})
	keyLoadDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "keyless_key_load_duration",
		Help:    "Time to load a requested key.",
		Buckets: durationBuckets,
	})
	connFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "keyless_failed_connection",
		Help: "Number of connection/transport failure, in tls handshake and etc.",
	})
)

func logRequest(opcode protocol.Op) {
	requests.WithLabelValues(opcode.String()).Inc()
}

func logConnFailure() {
	connFailures.Inc()
}

func logKeyLoadDuration(loadBegin time.Time) {
	keyLoadDuration.Observe(time.Since(loadBegin).Seconds())
}

// logRequestExecDuration logs the time taken to execute an operation (not
// including queueing).
func logRequestExecDuration(_ context.Context, opcode protocol.Op, requestBegin time.Time, err protocol.Error) {
	elapsed := time.Since(requestBegin)
	log.WithField("op", opcode.String()).
		WithField("elapsed", elapsed).
		WithField("error", err.Error()).
		Debugf("exec completed")
	requestExecDuration.WithLabelValues(opcode.Type(), err.String()).Observe(elapsed.Seconds())
}

func logRequestTotalDuration(_ context.Context, opcode protocol.Op, requestBegin time.Time, err protocol.Error) {
	elapsed := time.Since(requestBegin)
	log.WithField("op", opcode.String()).
		WithField("elapsed", elapsed).
		WithField("error", err.Error()).
		Debugf("request completed")
	requestTotalDuration.WithLabelValues(opcode.Type(), err.String()).Observe(elapsed.Seconds())
}

// MetricsListenAndServe serves Prometheus metrics at metricsAddr
func (s *Server) MetricsListenAndServe(metricsAddr string) error {
	if metricsAddr != "" {
		http.Handle("/metrics", promhttp.Handler())

		log.Infof("Serving metrics endpoint at %s/metrics\n", metricsAddr)
		return http.ListenAndServe(metricsAddr, nil)
	}
	return nil
}
