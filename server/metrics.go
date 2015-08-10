package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/go-metrics"
)

type statistics struct {
	rate        metrics.Meter
	invalidRate metrics.Meter
	latency     metrics.Timer
	metrics.Registry
}

func newStatistics(metricsAddr string) *statistics {
	stats := &statistics{
		rate:        metrics.NewMeter(),
		invalidRate: metrics.NewMeter(),
		latency:     metrics.NewTimer(),
		Registry:    metrics.NewRegistry(),
	}
	stats.Register("request_rate", stats.rate)
	stats.Register("invalid_request_rate", stats.invalidRate)
	stats.Register("response_latency", stats.latency)

	if metricsAddr != "" {
		go stats.ListenAndServe(metricsAddr)
	}

	return stats
}

// logInvalid increments the error count and updates the error percentage.
func (stats *statistics) logInvalid(requestBegin time.Time) {
	stats.invalidRate.Mark(1)
	stats.logRequest(requestBegin)
}

// logRequest increments the request count and updates the error percentage.
func (stats *statistics) logRequest(requestBegin time.Time) {
	stats.latency.UpdateSince(requestBegin)
	stats.rate.Mark(1)
}

func trueString(s string) bool {
	return s == "1" || strings.ToLower(s) == "true"
}

func (stats *statistics) serveJSON(w http.ResponseWriter, req *http.Request) {
	js, err := json.Marshal(stats.Registry)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	buf := bytes.NewBuffer(js)
	if trueString(req.URL.Query().Get("indent")) {
		buf = bytes.NewBuffer(nil)
		err = json.Indent(buf, js, "", "\t")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	content := bytes.NewReader(buf.Bytes())
	http.ServeContent(w, req, "metrics.json", time.Now(), content)
}

func (stats *statistics) ListenAndServe(addr string) {
	http.HandleFunc("/metrics", stats.serveJSON)
	http.HandleFunc("/metrics.js", stats.serveJSON)
	http.HandleFunc("/metrics.json", stats.serveJSON)

	log.Infof("Serving metrics endpoint at %s/metrics\n", addr)
	log.Critical(http.ListenAndServe(addr, nil))
}
