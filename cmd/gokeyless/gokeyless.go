package main

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
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
	flag.StringVar(&keyDir, "private-key-directory", "./keys", "Directory in which private keys are stored with .key extension")
	flag.StringVar(&port, "port", "2407", "Keyless port on which to listen")
	flag.StringVar(&metricsAddr, "metrics-addr", "localhost:2406", "address where the metrics API is served")
	flag.StringVar(&pidFile, "pid-file", "", "File to store PID of running server")
	flag.BoolVar(&manualMode, "manual-activation", false, "Manually activate the keyserver by writing the CSR to stderr")
}

func main() {
	flag.Parse()

	// Allow manual activation (requires the CSR to be manually signed).
	// manual activation won't proceed to start the server
	if manualMode {
		log.Info("now check server csr and key")
		if !verifyCSRAndKey() {
			log.Info("csr and key are not usable. generating server csr and key")
			manualActivation()

			log.Infof("contact CloudFlare for manual signing of csr in %q",
				csrFile)
		} else {
			log.Infof("csr at %q and private key at %q are already generated and verified correctly, please contact CloudFlare for manual signing",
				csrFile, keyFile)
		}
		os.Exit(0)
	}

	if needNewCertAndKey() {
		initializeServerCertAndKey()
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
			if needNewCertAndKey() {
				initializeServerCertAndKey()
				cert, err := tls.LoadX509KeyPair(certFile, keyFile)
				if err != nil {
					log.Fatalf("cannot load server cert/key: %v", err)
				}
				log.Info("server certificate is renewed")
				s.Config.Certificates = []tls.Certificate{cert}
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

// validCertExpiry checks if cerficiate is currently valid.
func validCertExpiry(cert *x509.Certificate) bool {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return false
	}

	if now.After(cert.NotAfter) {
		return false
	}

	// certificate expires in a month
	if now.Add(time.Hour * 24 * 30).After(cert.NotAfter) {
		log.Warning("server certificate is expiring in 30 days")
	}

	return true
}

// needNewCertAndKey checks the validity of certificate and key
func needNewCertAndKey() bool {
	_, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Errorf("cannot load server cert/key: %v", err)
		return true
	}

	// error is ignore because tls.LoadX509KeyPair already verify the existence of the file
	certBytes, _ := ioutil.ReadFile(certFile)
	// error is ignore because tls.LoadX509KeyPair already verify the file can be parsed
	cert, _ := helpers.ParseCertificatePEM(certBytes)
	// verify the leaf certificate
	if cert == nil || !validCertExpiry(cert) {
		log.Errorf("certificate is either not yet valid or expired")
		return true
	}

	return false
}

// verifyCSRAndKey checks if csr and key files exist and if they match
func verifyCSRAndKey() bool {
	csrBytes, err := ioutil.ReadFile(csrFile)
	if err != nil {
		log.Errorf("cannot read csr file: %v", err)
		return false
	}

	csr, err := helpers.ParseCSRPEM(csrBytes)
	if err != nil {
		log.Errorf("cannot parse csr file: %v", err)
		return false
	}

	if err := csr.CheckSignature(); err != nil {
		log.Errorf("cannot verify csr signature: %v", err)
		return false
	}

	csrPubKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		log.Errorf("cannot serialize public key from csr: %v", err)
		return false
	}

	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		log.Errorf("cannot read private key file: %v", err)
		return false
	}

	key, err := helpers.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		log.Errorf("cannot parse private key file: %v", err)
		return false
	}

	pubkey, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		log.Errorf("cannot serialize public key from private key: %v", err)
		return false
	}

	if !bytes.Equal(pubkey, csrPubKey) {
		log.Errorf("csr doesn't match with private key")
		return false
	}

	return true
}
