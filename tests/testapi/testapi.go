package testapi

import (
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/go-metrics"
)

// Input is a JSON struct representing a test suite to be run.
type Input struct {
	Keyserver          string `json:"keyserver"`
	CertsPEM           string `json:"certs,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	SNI                string `json:"sni,omitempty"`
	ServerIP           string `json:"sni,omitempty"`
}

// Results represents the success stats of an entire test suite.
type Results struct {
	Tests         map[string]*Test `json:"tests"`
	latency       metrics.Timer
	totalTests    metrics.Counter
	totalFailures metrics.Counter
	metrics.Registry
}

// NewResults initializes a new API Results struct.
func NewResults() *Results {
	results := &Results{
		Tests:         make(map[string]*Test),
		latency:       metrics.NewTimer(),
		totalTests:    metrics.NewCounter(),
		totalFailures: metrics.NewCounter(),
		Registry:      metrics.NewRegistry(),
	}
	results.Register("latency", results.latency)
	results.Register("total_tests", results.totalTests)
	results.Register("total_failures", results.totalFailures)
	return results
}

// TestFunc represents generic test to be run.
type TestFunc func() error

// Test represents the success stats for an individual test.
type Test struct {
	latency  metrics.Timer
	tests    metrics.Counter
	failures metrics.Counter
	Errors   []error `json:"errors,omitempty"`
	run      TestFunc
}

// RegisterTest initializes a new Test struct and adds it to results.
func (results *Results) RegisterTest(name string, run TestFunc) {
	results.Tests[name] = &Test{
		latency:  metrics.NewTimer(),
		tests:    metrics.NewCounter(),
		failures: metrics.NewCounter(),
		run:      run,
	}
	results.Register(name+".latency", results.Tests[name].latency)
	results.Register(name+".tests", results.Tests[name].tests)
	results.Register(name+".failures", results.Tests[name].failures)
}

// RunTests continually runs the tests stored in results for testLen.
func (results *Results) RunTests(testLen time.Duration, workers int) {
	log.Debugf("Running tests for %v with %d workers", testLen, workers)
	tests := make(chan string, workers)
	for i := 0; i < workers; i++ {
		go func() {
			for name := range tests {
				log.Debugf("Running %s", name)
				testStart := time.Now()
				t := results.Tests[name]
				if err := t.run(); err != nil {
					t.failures.Inc(1)
					results.totalFailures.Inc(1)
					t.Errors = append(t.Errors, err)
					log.Debug(err)
				}
				t.tests.Inc(1)
				results.totalTests.Inc(1)
				t.latency.UpdateSince(testStart)
				results.latency.UpdateSince(testStart)
			}
		}()
	}

	timeout := time.After(testLen)
	for {
		for name := range results.Tests {
			select {
			case <-timeout:
				close(tests)
				return

			case tests <- name:
			}
		}
	}
}
