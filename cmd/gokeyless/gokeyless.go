package main

import (
	"crypto"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/server"
)

var (
	port        string
	metricsPort string
	initCert    bool
	certFile    string
	keyFile     string
	caFile      string
	keyDir      string
	pidFile     string
)

func init() {
	flag.BoolVar(&initCert, "init", false, "Initialize new server authentication key and certificate")
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
	if initCert {
		var hosts string
		fmt.Print("Keyserver Hostnames/IPs (comma-seperated): ")
		fmt.Scanln(&hosts)

		csr, key, err := csr.ParseRequest(&csr.CertificateRequest{
			CN:         "Keyless Server Authentication Certificate",
			Hosts:      strings.Split(hosts, ","),
			KeyRequest: &csr.KeyRequest{Algo: "ecdsa", Size: 384},
		})
		if err != nil {
			log.Fatal(err)
		}

		if err := ioutil.WriteFile(keyFile, key, 0400); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Key generated and saved to %s\n", keyFile)

		fmt.Printf("Email this CSR to keyless-csr@cloudflare.com for signing and save the resulting certificate to %s:\n", certFile)
		fmt.Print(string(csr))
		return
	}

	s, err := server.NewServerFromFile(certFile, keyFile, caFile,
		net.JoinHostPort("", port), net.JoinHostPort("", metricsPort))
	if err != nil {
		log.Warningf("Could not create server. Run `gokeyless -init` to get %s and %s", keyFile, certFile)
		log.Fatal(err)
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
