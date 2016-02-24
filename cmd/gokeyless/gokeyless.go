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
	initToken    string
	initCertFile string
	initKeyFile  string
	initEndpoint string
	port         string
	metricsPort  string
	certFile     string
	keyFile      string
	caFile       string
	keyDir       string
	pidFile      string
)

func init() {
	flag.StringVar(&initToken, "init-token", "token.json", "API token used for server initialization")
	flag.StringVar(&initCertFile, "init-cert", "default.pem", "Default certificate used for server initialization")
	flag.StringVar(&initKeyFile, "init-key", "default-key.pem", "Default key used for server initialization")
	flag.StringVar(&initEndpoint, "init-endpoint", "https://api.cloudflare.com/client/v4/certificates", "API endpoint for server initialization")
	flag.StringVar(&certFile, "cert", "server.pem", "Keyless server authentication certificate")
	flag.StringVar(&keyFile, "key", "server-key.pem", "Keyless server authentication key")
	flag.StringVar(&caFile, "ca-file", "keyless_cacert.pem", "Keyless client certificate authority")
	flag.StringVar(&keyDir, "private-key-directory", "keys/", "Directory in which private keys are stored with .key extension")
	flag.StringVar(&port, "port", "2407", "Keyless port on which to listen")
	flag.StringVar(&metricsPort, "metrics-port", "2406", "Port where the metrics API is served")
	flag.IntVar(&log.Level, "loglevel", 1, "Degree of logging")
	flag.StringVar(&pidFile, "pid-file", "", "File to store PID of running server")
	flag.Parse()
}

func main() {
	s, err := server.NewServerFromFile(certFile, keyFile, caFile,
		net.JoinHostPort("", port), net.JoinHostPort("", metricsPort))
	if err != nil {
		log.Warningf("Could not create server. Running initializeServer to get %s and %s", keyFile, certFile)
		s = initializeServer()
	}

	if err := s.LoadKeysFromDir(keyDir, LoadKey); err != nil {
		log.Fatal(err)
	}

	// Start server in background, then listen for SIGHUPs to reload keys.
	go func() {
		log.Fatal(s.ListenAndServe())
	}()

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
