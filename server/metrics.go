package server

import (
	"net/http"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/protocol"
	"github.com/prometheus/client_golang/prometheus"
)

type statistics struct {
	requestExecDuration          prometheus.Summary
	requestTotalDuration         prometheus.Summary
	requestExecDurationByOpcode  *prometheus.SummaryVec
	requestTotalDurationByOpcode *prometheus.SummaryVec
	requestsInvalid              prometheus.Counter
	connFailures                 prometheus.Counter
	queuedECDSARequests          prometheus.Gauge
	queuedOtherRequests          prometheus.Gauge
	requestOpcodes               *prometheus.CounterVec
}

func newStatistics() *statistics {
	return &statistics{
		requestExecDuration: prometheus.NewSummary(prometheus.SummaryOpts{
			Name: "keyless_request_execution_duration",
			Help: "Time to execute a request not including time in queues.",
		}),
		requestTotalDuration: prometheus.NewSummary(prometheus.SummaryOpts{
			Name: "keyless_request_total_duration",
			Help: "Total time to satisfy a request including time in queues.",
		}),
		requestExecDurationByOpcode: prometheus.NewSummaryVec(prometheus.SummaryOpts{
			Name: "keyless_request_exec_duration_per_opcode",
			Help: "Time to execute a request not including time in queues, broken down by opcode.",
		}, []string{"opcode"}),
		requestTotalDurationByOpcode: prometheus.NewSummaryVec(prometheus.SummaryOpts{
			Name: "keyless_request_total_duration_per_opcode",
			Help: "Total time to satisfy a request including time in queues, broken down by opcode.",
		}, []string{"opcode"}),
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
		requestOpcodes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "keyless_request_opcodes",
			Help: "Number of requests received with various opcodes.",
		}, []string{"opcode"}),
	}
}

// logInvalid increments the error count and updates the error percentage.
func (stats *statistics) logInvalid(opcode protocol.Op, requestBegin time.Time) {
	stats.requestsInvalid.Inc()
	stats.logRequestExecDuration(opcode, requestBegin)
}

// logConnFailure increments the error count of connFailures.
func (stats *statistics) logConnFailure() {
	stats.connFailures.Inc()
}

func (stats *statistics) logRequestExecDuration(opcode protocol.Op, requestBegin time.Time) {
	stats.requestExecDuration.Observe(float64(time.Now().Sub(requestBegin)) / float64(time.Second))
	stats.requestExecDurationByOpcode.WithLabelValues(opcode.String()).
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

func (stats *statistics) logRequestOpcode(opcode protocol.Op) {
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
		s.stats.requestsInvalid,
		s.stats.connFailures,
		s.stats.queuedECDSARequests,
		s.stats.queuedOtherRequests,
		s.stats.requestOpcodes,
	)
}
