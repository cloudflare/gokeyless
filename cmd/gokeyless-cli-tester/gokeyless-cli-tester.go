package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/client"
	"github.com/cloudflare/gokeyless/delegated"
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
	delegate           bool
	workers            int
	repeats            int
	testLen            time.Duration
	delegateCert       string
)

func init() {
	flag.IntVar(&log.Level, "loglevel", log.LevelInfo, "Log level (0 = DEBUG, 5 = FATAL)")
	flag.StringVar(&certFile, "cert", "client.pem", "Keyless server authentication certificate")
	flag.StringVar(&keyFile, "key", "client-key.pem", "Keyless server authentication key")
	flag.StringVar(&caFile, "ca-file", "keyserver_cacert.pem", "Keyless server certificate authority")
	flag.StringVar(&keyserver, "keyserver", "", "Keyless server, in the form [host:port]")
	flag.BoolVar(&insecureSkipVerify, "no-verify", false, "Don't verify server certificate against Keyserver CA")
	flag.BoolVar(&benchmark, "benchmark", false, "run test in benchmark mode")
	flag.BoolVar(&delegate, "delegate", false, "get delegated credentials")
	flag.StringVar(&certDir, "cert-directory", "certs/", "Directory in which certificates are stored with .crt extension")
	flag.IntVar(&workers, "workers", 8, "Number of concurrent connections to keyserver")
	flag.IntVar(&repeats, "repeats", 0, "Number of test repeats")
	flag.DurationVar(&testLen, "testlen", 5*time.Second, "test length in seconds")
	flag.StringVar(&delegateCert, "delegatecert", "", "cert we want to get a delegation for")
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
	if delegate {
		r, err := c.LookupServer(keyserver)
		if err != nil {
			log.Fatal("Could not look up keyserver", err)
		}
		conn, err := r.Dial(c)
		if err != nil {
			log.Fatal("Could not establish connection", err)
		}
		rpc := conn.RPC()

		//I imagine all kinds of stuff will eventually get passed to this function
		certfile, err := os.Open(delegateCert)
		if err != nil {
			log.Fatal("Could not open cert we want to get delegation from", err)
		}
		pemblock, err := ioutil.ReadAll(certfile)
		if err != nil {
			log.Fatal("Could not glob file", err)
		}
		certblock, _ := pem.Decode(pemblock)
		cert, err := x509.ParseCertificate(certblock.Bytes)
		if err != nil {
			log.Fatal("Could not parse certificate", err)
		}
		notBefore := cert.NotBefore
		ttl := time.Now().Sub(notBefore) + 3*1e12 //Or any time really
		cred, _, err := delegated.NewCredential(uint16(tls.ECDSAWithP256AndSHA256), delegated.VersionTLS13, ttl)
		req, err := cred.Marshal()
		if err != nil {
			log.Fatal("failed to create query", err)
		}
		var resp []byte
		err = rpc.Call("Delegator.Sign", req, &resp) //Richer queries and responses would be a good idea
		if err != nil {
			log.Fatal("failed in RPC", err)
		}
		dc, err := delegated.UnmarshalDelegatedCredential(resp)
		if err != nil {
			log.Fatal("failed to parse response")
		}
		valid, err := dc.Validate(cert, time.Now())
		if err != nil {
			log.Fatal("Error in validation", err)
		}
		if !valid {
			log.Fatal("Got invalid response")
		}
		log.Fatalf("Got valid response")
		log.Fatalf("Got response %v", resp)
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
