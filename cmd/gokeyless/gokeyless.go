package main

import (
	"crypto"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

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
	initCertFile string
	initKeyFile  string
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

func init() {
	flag.IntVar(&log.Level, "loglevel", log.LevelInfo, "Log level (0 = DEBUG, 5 = FATAL)")
	flag.StringVar(&initToken, "init-token", "token.json", "API token used for server initialization")
	flag.StringVar(&initCertFile, "init-cert", "default.pem", "Default certificate used for server initialization")
	flag.StringVar(&initKeyFile, "init-key", "default-key.pem", "Default key used for server initialization")
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

	s, err := server.NewServerFromFile(certFile, keyFile, caFile, net.JoinHostPort("", port), "")
	if err != nil {
		log.Warningf("Could not create server. Running initializeServer to get %s and %s", keyFile, certFile)

		// If an existing CSR (and associated key) exists, don't
		// proceed/overwrite the key.
		if _, err := os.Stat(csrFile); !os.IsNotExist(err) {
			log.Fatalf("an existing CSR was found at %q: remove once a signed certificate has been installed.", csrFile)
		}

		// Allow manual activation (requires the CSR to be manually signed).
		if manualMode {
			if err := manualActivation(); err != nil {
				log.Fatal(err)
			}

			log.Infof("CSR generated (requires manual signing) and written to %q",
				csrFile)
			os.Exit(0)
		} else {
			// Automatically activate against the certificate API.
			s = initializeServer()
		}
	}

	go func() { log.Fatal(s.ListenAndServe()) }()
	go func() { log.Critical(s.MetricsListenAndServe(metricsAddr)) }()

	if err := s.LoadKeysFromDir(keyDir, LoadKey); err != nil {
		log.Fatal(err)
	}

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
			if err := s.LoadKeysFromDir(keyDir, LoadKey); err != nil {
				log.Fatal(err)
			}
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
