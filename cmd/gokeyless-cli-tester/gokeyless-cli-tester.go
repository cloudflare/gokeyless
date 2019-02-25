package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/client"
	"github.com/cloudflare/gokeyless/protocol"
	"github.com/cloudflare/gokeyless/tests"
)

var (
	certFile           string
	keyFile            string
	caFile             string
	keyserver          string
	certDir            string
	insecureSkipVerify bool
	benchmark          bool
	workers            int
	repeats            int
	testLen            time.Duration
)

func init() {
	flag.IntVar(&log.Level, "loglevel", log.LevelInfo, "Log level (0 = DEBUG, 5 = FATAL)")
	flag.StringVar(&certFile, "cert", "client.pem", "Keyless server authentication certificate")
	flag.StringVar(&keyFile, "key", "client-key.pem", "Keyless server authentication key")
	flag.StringVar(&caFile, "ca-file", "keyserver_cacert.pem", "Keyless server certificate authority")
	flag.StringVar(&keyserver, "keyserver", "", "Keyless server, in the form [host:port]")
	flag.BoolVar(&insecureSkipVerify, "no-verify", false, "Don't verify server certificate against Keyserver CA")
	flag.BoolVar(&benchmark, "benchmark", false, "run test in benchmark mode")
	flag.StringVar(&certDir, "cert-directory", "certs/", "Directory in which certificates are stored with .crt extension")
	flag.IntVar(&workers, "workers", 8, "Number of concurrent connections to keyserver")
	flag.IntVar(&repeats, "repeats", 0, "Number of test repeats")
	flag.DurationVar(&testLen, "testlen", 5*time.Second, "test length in seconds")
	flag.Parse()
}

func main() {
	c, err := client.NewClientFromFile(certFile, keyFile, caFile)
	if err != nil {
		log.Fatal(err)
	}
	c.Config.InsecureSkipVerify = insecureSkipVerify
	privs, err := c.ScanDir(keyserver, certDir, nil)
	if err != nil {
		log.Fatal("failed to load cert directory:", err)
	}
	results := tests.NewResults()
	results.RegisterTest("ping", tests.NewPingTest(c, keyserver))
	for _, priv := range privs {
		ski, _ := protocol.GetSKI(priv.Public())
		for name, test := range tests.NewSignTests(priv) {
			results.RegisterTest(ski.String()+"."+name, test)
		}
	}

	if benchmark {
		results.RunBenchmarkTests(repeats, workers)
	} else {
		results.RunTests(testLen, workers)
	}
	resultsJSON, err := json.MarshalIndent(results, "", "\t")
	if err != nil {
		log.Fatal("failed to marshal results:", err)
	}

	fmt.Println(string(resultsJSON))

}
