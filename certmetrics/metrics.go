// Package certmetrics will be used to register and emit metrics for certificates in memory
package certmetrics

import (
	"crypto/x509"
	"sort"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var certificateExpirationTimes = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "certificate_expiration_timestamp_seconds",
		Help: "Expiration times of gokeyless certs",
	},
	[]string{"serial_no", "cn", "hostnames", "ca", "server", "client"},
)

// Observe takes in a list of certs and emits its expiration times
func Observe(certs ...*x509.Certificate) {
	for _, cert := range certs {
		hostnames := cert.DNSNames
		sort.Strings(hostnames)
		labels := prometheus.Labels{
			"serial_no": cert.SerialNumber.String(),
			"cn":        cert.Subject.CommonName,
			"hostnames": strings.Join(hostnames, ","),
			"ca":        boolToBinaryString(cert.IsCA),
			"server":    containsKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth),
			"client":    containsKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)}
		certificateExpirationTimes.With(labels).Set(float64(cert.NotAfter.Unix()))
	}
}

func boolToBinaryString(val bool) string {
	if val {
		return "1"
	}
	return "0"
}

func containsKeyUsage(a []x509.ExtKeyUsage, x x509.ExtKeyUsage) string {
	for _, e := range a {
		if e == x || e == x509.ExtKeyUsageAny {
			return "1"
		}
	}
	return "0"
}
