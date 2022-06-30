// Package certmetrics will be used to register and emit metrics for certificates in memory
package certmetrics

import (
	"crypto/x509"
	"io/ioutil"
	"os"
	"sort"
	"strings"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var certificateExpirationTimes = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "certificate_expiration_timestamp_seconds",
		Help: "Expiration times of gokeyless certs",
	},
	[]string{"source", "serial_no", "cn", "hostnames", "ca", "server", "client"},
)

// Observe takes in a list of certs and emits its expiration times
func Observe(certs ...CertSource) {
	for _, cert := range certs {
		certificateExpirationTimes.With(getPrometheusLabels(cert)).Set(float64(cert.Cert.NotAfter.Unix()))
	}
}

// pemCertsFromFile reads PEM format certificates from a file.
func certSourceFromFile(path string) ([]CertSource, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	pemData, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	certs, err := helpers.ParseCertificatesPEM(pemData)
	if err != nil {
		return nil, err
	}
	return CertSourceFromCerts(path, certs), nil

}

// GatherFromPaths discovers certs in the given paths
func GatherFromPaths(certPaths []string) (allCerts []CertSource, err error) {
	for _, cPath := range certPaths {
		if cPath == "" {
			continue
		}
		pemCerts, err := certSourceFromFile(cPath)
		if err != nil {
			return nil, err
		}
		allCerts = append(allCerts, pemCerts...)
	}
	return allCerts, nil
}

// CertSourceFromCerts creates a wrapper all with same source
func CertSourceFromCerts(source string, certs []*x509.Certificate) (res []CertSource) {
	for _, x := range certs {
		res = append(res, CertSource{
			Source: source,
			Cert:   x,
		})
	}
	return
}

// CertSource holds a cert and a reference to where it came from
type CertSource struct {
	Source string
	Cert   *x509.Certificate
}

func getPrometheusLabels(c CertSource) prometheus.Labels {
	cert := c.Cert
	hostnames := append([]string(nil), cert.DNSNames...)
	sort.Strings(hostnames)
	return prometheus.Labels{
		"source":    c.Source,
		"serial_no": cert.SerialNumber.String(),
		"cn":        cert.Subject.CommonName,
		"hostnames": strings.Join(hostnames, ","),
		"ca":        boolToBinaryString(cert.IsCA),
		"server":    hasKeyUsageAsBinaryString(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth),
		"client":    hasKeyUsageAsBinaryString(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)}
}

func boolToBinaryString(val bool) string {
	if val {
		return "1"
	}
	return "0"
}

func hasKeyUsageAsBinaryString(a []x509.ExtKeyUsage, x x509.ExtKeyUsage) string {
	for _, e := range a {
		if e == x || e == x509.ExtKeyUsageAny {
			return "1"
		}
	}
	return "0"
}
