package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/client"
	"github.com/cloudflare/gokeyless/tests"
	"github.com/cloudflare/gokeyless/tests/testapi"
)

var (
	certFile           string
	keyFile            string
	caFile             string
	insecureSkipVerify bool
	workers            int
	testLen            time.Duration
	testcerts          string
	domain             string
	serverIP           string
	server             string
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
	flag.StringVar(&server, "server", "", "(Optional) Keyless server to test")
	flag.StringVar(&testcerts, "testcerts", "", "(Optional) Certificate(s) to test on keyserver")
	flag.StringVar(&domain, "domain", "", "(Optional) Site domain")
	flag.StringVar(&serverIP, "server-ip", "", "(Optional) Lazyloading Server IP")
	flag.StringVar(&apiPort, "api-port", "", "(Opitional) Port on which to spawn test API listener.")
	flag.Parse()
}

func main() {
	c, err := client.NewClientFromFile(certFile, keyFile, caFile)
	if err != nil {
		log.Fatal(err)
	}
	c.Config.InsecureSkipVerify = insecureSkipVerify

	if server != "" {
		in := &testapi.Input{
			Keyserver: server,
			CertsPEM:  testcerts,
			Domain:    domain,
			ServerIP:  serverIP,
		}
		results, err := tests.RunAPITests(in, c, testLen, workers)
		if err != nil {
			log.Fatal(err)
		}
		out, err := json.MarshalIndent(results.Registry, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(out))
	}

	if apiPort != "" {
		log.Fatal(tests.ListenAndServeAPI(net.JoinHostPort("", apiPort), testLen, workers, c))
	}
}
