package main

import (
	"flag"
	"net"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/client"
	"github.com/cloudflare/gokeyless/tests"
)

var (
	certFile           string
	keyFile            string
	caFile             string
	insecureSkipVerify bool
	workers            int
	testLen            time.Duration
	apiPort            string
)

func init() {
	flag.IntVar(&log.Level, "loglevel", 1, "Degree of logging")
	flag.StringVar(&certFile, "cert", "client.pem", "Keyless server authentication certificate")
	flag.StringVar(&keyFile, "key", "client-key.pem", "Keyless server authentication key")
	flag.StringVar(&caFile, "ca-file", "keyserver_cacert.pem", "Keyless server certificate authority")
	flag.BoolVar(&insecureSkipVerify, "no-verify", false, "Don't verify server certificate against Keyserver CA")
	flag.IntVar(&workers, "workers", 8, "Number of concurrent connections to keyserver")
	flag.DurationVar(&testLen, "testlen", 5*time.Second, "test length in seconds")
	flag.StringVar(&apiPort, "api-port", "8080", "Port on which to spawn test API listener.")
	flag.Parse()
}

func main() {
	c, err := client.NewClientFromFile(certFile, keyFile, caFile)
	if err != nil {
		log.Fatal(err)
	}
	c.Config.InsecureSkipVerify = insecureSkipVerify

	clients := map[string]*client.Client{
		"prod": c,
	}

	log.Fatal(tests.ListenAndServeAPI(net.JoinHostPort("", apiPort), testLen, workers, clients))
}
