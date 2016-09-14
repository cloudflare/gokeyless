package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/server"
)

var (
	defaultEndpoint = "https://api.cloudflare.com/client/v4/certificates/"
	csrFile         = "server.csr"
)

var (
	initToken    string
	initEndpoint string
	port         string
	metricsAddr  string
	certFile     string
	keyFile      string
	caFile       string
	keyDir       string
	pidFile      string
	manualMode   bool
)

type CertError error

func init() {
	flag.IntVar(&log.Level, "loglevel", log.LevelInfo, "Log level (0 = DEBUG, 5 = FATAL)")
	flag.StringVar(&initToken, "init-token", "token.json", "API token used for server initialization")
	flag.StringVar(&initEndpoint, "init-endpoint", defaultEndpoint, "API endpoint for server initialization")
	flag.StringVar(&certFile, "cert", "server.pem", "Keyless server authentication certificate")
	flag.StringVar(&keyFile, "key", "server-key.pem", "Keyless server authentication key")
	flag.StringVar(&caFile, "ca-file", "keyless_cacert.pem", "Keyless client certificate authority")
	flag.StringVar(&keyDir, "private-key-directory", "keys/", "Directory in which private keys are stored with .key extension")
	flag.StringVar(&port, "port", "2407", "Keyless port on which to listen")
	flag.StringVar(&metricsAddr, "metrics-addr", "localhost:2406", "address where the metrics API is served")
	flag.StringVar(&pidFile, "pid-file", "", "File to store PID of running server")
	flag.BoolVar(&manualMode, "manual-activation", false, "Manually activate the keyserver by writing the CSR to stderr")
}

func main() {
	flag.Parse()

	init := needNewCertAndKey()
	if init {
		log.Info("Now let's get server certificate and key")
		// Allow manual activation (requires the CSR to be manually signed).
		if manualMode {
			log.Info("[Manual mode]")
			if err := manualActivation(); err != nil {
				log.Fatal(err)
			}

			log.Infof("CSR generated (requires manual signing) and written to %q",
				csrFile)
			log.Info("We are done, please contact support for getting the CSR signed into a certificate")
			os.Exit(0)
		} else {
			log.Info("[Automatic mode]")
			// Automatically activate against the certificate API.
			initializeServerCertAndKey()
		}
	}

	s, err := server.NewServerFromFile(certFile, keyFile, caFile, net.JoinHostPort("", port), "")
	if err != nil {
		log.Fatal("cannot start server:", err)
	}

	go func() { log.Fatal(s.ListenAndServe()) }()
	go func() { log.Critical(s.MetricsListenAndServe(metricsAddr)) }()

	keys := server.NewDefaultKeystore()
	if err := keys.LoadKeysFromDir(keyDir, LoadKey); err != nil {
		log.Fatal(err)
	}
	s.Keys = keys

	if pidFile != "" {
		if f, err := os.Create(pidFile); err != nil {
			log.Errorf("error creating pid file: %v", err)
		} else {
			fmt.Fprintf(f, "%d", os.Getpid())
			f.Close()
		}
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	for {
		select {
		case <-c:
			log.Info("Received SIGHUP, reloading keys...")
			keys := server.NewDefaultKeystore()
			if err := keys.LoadKeysFromDir(keyDir, LoadKey); err != nil {
				log.Fatal(err)
			}
			s.Keys = keys

			log.Info("Check server certificate...")
			needRenewal := needNewCertAndKey()
			if needRenewal {
				if manualMode {
					log.Fatalf("please contact support to get certificate renewed")
				} else {
					initializeServerCertAndKey()
					cert, err := tls.LoadX509KeyPair(certFile, keyFile)
					if err != nil {
						log.Fatalf("cannot load server cert/key: %v", err)
					}
					log.Info("server certificate is renewed")
					s.Config.Certificates = []tls.Certificate{cert}
				}
			}
			log.Info("server certificate is valid, restart completes")
		}
	}
}

// LoadKey attempts to load a private key from PEM or DER.
func LoadKey(in []byte) (priv crypto.Signer, err error) {
	priv, err = helpers.ParsePrivateKeyPEM(in)
	if err == nil {
		return priv, nil
	}

	return derhelpers.ParsePrivateKeyDER(in)
}

func validCert(cert *x509.Certificate) bool {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return false
	}

	if now.After(cert.NotAfter) {
		return false
	}

	// certificate expires in a month
	if now.Add(time.Hour * 24 * 30).After(cert.NotAfter) {
		return false
	}

	return true
}
func needNewCertAndKey() bool {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Errorf("cannot load server cert/key: %v", err)
		return true
	}

	if !validCert(cert.Leaf) {
		log.Errorf("certificate is either not yet valid, expired or expiring in a month")
		return true
	}

	return false
}

func manualActivation() error {
	token := tokenPrompt()
	csr, _, err := generateCSR(token.Host)
	if err != nil {
		return err
	}

	f, err := os.Create(csrFile)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(csr)
	return err
}
