// +build go1.8

package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/cloudflare/gokeyless/client"
	bclient "github.com/cloudflare/gokeyless/cmd/bench/internal/client"
	"github.com/cloudflare/gokeyless/internal/test/params"
	"github.com/cloudflare/gokeyless/protocol"
)

var (
	certFileFlag string
	keyFileFlag  string
	caFileFlag   string
	sniFlag      string
	serverIPFlag string
	skiFlag      string
	opFlag       string
	serverFlag   string
	portFlag     uint64

	bwFlag                     bool
	gmpFlag                    int
	workersFlag                int
	durFlag                    time.Duration
	minFlag, maxFlag, stepFlag time.Duration
	pauseFlag                  time.Duration

	ops = map[string]func(protocol.Operation) protocol.Operation{
		"ECDSA-SHA224": makeECDSASignOpMaker(params.ECDSASHA224Params),
		"ECDSA-SHA256": makeECDSASignOpMaker(params.ECDSASHA256Params),
		"ECDSA-SHA384": makeECDSASignOpMaker(params.ECDSASHA384Params),
		"ECDSA-SHA512": makeECDSASignOpMaker(params.ECDSASHA512Params),
		"RSA-MD5SHA1":  makeRSASignOpMaker(params.RSAMD5SHA1Params),
		"RSA-SHA1":     makeRSASignOpMaker(params.RSASHA1Params),
		"RSA-SHA224":   makeRSASignOpMaker(params.RSASHA224Params),
		"RSA-SHA256":   makeRSASignOpMaker(params.RSASHA256Params),
		"RSA-SHA384":   makeRSASignOpMaker(params.RSASHA384Params),
		"RSA-SHA512":   makeRSASignOpMaker(params.RSASHA512Params),
	}
)

func makeECDSASignOpMaker(params params.ECDSASignParams) func(op protocol.Operation) protocol.Operation {
	return func(op protocol.Operation) protocol.Operation { return makeECDSASignOp(params, op) }
}

func makeRSASignOpMaker(params params.RSASignParams) func(op protocol.Operation) protocol.Operation {
	return func(op protocol.Operation) protocol.Operation { return makeRSASignOp(params, op) }
}

func init() {
	flag.StringVar(&certFileFlag, "cert", "../../client/testdata/client.pem", "file containing the client certificate")
	flag.StringVar(&keyFileFlag, "key", "../../client/testdata/client-key.pem", "file containing the client key")
	flag.StringVar(&caFileFlag, "ca", "../../client/testdata/ca.pem", "file containing the CA certificate")
	flag.StringVar(&sniFlag, "sni", "localhost", "SNI of the certificate to request a signature for")
	flag.StringVar(&serverIPFlag, "server-ip", "127.0.0.1", "IP address of the certificate to request a signature for")
	flag.StringVar(&skiFlag, "ski", "D9C69B8E23ABBA7C26FD5D0E282F3DD679741036", "SKI of the key to request a signature from")
	flag.StringVar(&opFlag, "op", "ECDSA-SHA512", "the operation to request from the server")
	flag.StringVar(&serverFlag, "server", "localhost", "keyless server to connect to")
	flag.Uint64Var(&portFlag, "port", 2407, "port to connect to the keyless server on")

	flag.BoolVar(&bwFlag, "bandwidth", false, "perform a bandwidth test rather than a latency test")
	flag.IntVar(&gmpFlag, "gmp", runtime.GOMAXPROCS(0), "override the default GOMAXPROCS")
	flag.IntVar(&workersFlag, "workers", runtime.NumCPU(), "the number of worker goroutines to use")
	flag.DurationVar(&durFlag, "duration", 10*time.Second, "the duration to run the test for")
	flag.DurationVar(&minFlag, "histogram-min", 0, "minimum duration bucket for the histogram (default 0ns)")
	flag.DurationVar(&maxFlag, "histogram-max", time.Millisecond, "maximum duration bucket for the histogram")
	flag.DurationVar(&stepFlag, "histogram-step", 20*time.Microsecond, "histogram bucket width")
	flag.DurationVar(&pauseFlag, "pause", 10*time.Millisecond, "for latency tests, the amount of time to wait between each request")
}

func main() {
	flag.Parse()
	if portFlag > uint64(math.MaxUint16) {
		fmt.Fprintln(os.Stderr, "port out of range: must be in [0, 65535]")
		flag.Usage()
		os.Exit(2) // same code flag package uses for usage errors
	}

	var op protocol.Operation

	// strip any colons so that AA:BB:CC:DD format works
	skiBytes, err := hex.DecodeString(strings.Replace(skiFlag, ":", "", -1))
	if err != nil || len(skiBytes) != 20 {
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not parse SKI as hex: %v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, "SKI must be 20 bytes (40 hex characters)")
		}
		flag.Usage()
		os.Exit(2) // same code flag package uses for usage errors
	}
	copy(op.SKI[:], skiBytes)

	if serverIPFlag != "" {
		ip := net.ParseIP(serverIPFlag)
		if ip == nil {
			fmt.Fprintf(os.Stderr, "could not parse IP %q\n", ip)
			os.Exit(2) // same code flag package uses for usage errors
		}
		op.ServerIP = ip
	}

	if sniFlag != "" {
		op.SNI = sniFlag
	}

	opFn, ok := ops[opFlag]
	if !ok {
		fmt.Fprintf(os.Stderr, "unrecognized signing operation: %v", opFlag)
		os.Exit(2) // same code flag package uses for usage errors
	}

	op = opFn(op)

	runtime.GOMAXPROCS(gmpFlag)

	cli, err := client.NewClientFromFile(certFileFlag, keyFileFlag, caFileFlag)
	if err != nil {
		panic(err)
	}

	if bwFlag {
		// Run a bandwidth test
		var clients []bclient.BandwidthClient
		for i := 0; i < workersFlag; i++ {
			c, err := makeBandwidthClientFromOp(cli, serverFlag, fmt.Sprint(portFlag), op)
			if err != nil {
				panic(err)
			}
			clients = append(clients, c)
		}

		count := bclient.RunBandwidthClients(durFlag, clients...)
		fmt.Println("Total operations completed:", count)
		fmt.Println("Average operation duration:", (durFlag)/time.Duration(count))
	} else {
		// Run a latency test
		var clients []bclient.LatencyClient
		for i := 0; i < workersFlag; i++ {
			c, err := makeLatencyClientFromOp(cli, serverFlag, fmt.Sprint(portFlag), op)
			if err != nil {
				panic(err)
			}
			clients = append(clients, c)
		}

		buckets := bclient.RunLatencyClients(durFlag, minFlag, maxFlag, stepFlag, clients...)
		bclient.PrintHistogram(buckets)
	}
}

type bwClient struct {
	pkt  []byte
	conn *tls.Conn
}

func (b *bwClient) Dispatch() {
	_, err := b.conn.Write(b.pkt)
	if err != nil {
		panic(err)
	}
}

func (b *bwClient) Complete() {
	readPacket(b.conn)
}

func readPacket(conn *tls.Conn) {
	var buf [8]byte
	_, err := io.ReadFull(conn, buf[:])
	if err != nil {
		panic(err)
	}

	var pkt protocol.Packet
	err = pkt.UnmarshalBinary(buf[:])
	if err != nil {
		panic(err)
	}

	body := make([]byte, pkt.Length)
	_, err = io.ReadFull(conn, body)
	if err != nil {
		panic(err)
	}
}

func makeBandwidthClientFromOp(cli *client.Client, server, port string, op protocol.Operation) (bclient.BandwidthClient, error) {
	conn := dial(cli, server, port)
	pkt := protocol.NewPacket(0, op)
	buf, err := pkt.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return &bwClient{
		pkt:  buf,
		conn: conn,
	}, nil
}

func makeLatencyClientFromOp(cli *client.Client, server, port string, op protocol.Operation) (bclient.LatencyClient, error) {
	conn := dial(cli, server, port)
	pkt := protocol.NewPacket(0, op)
	buf, err := pkt.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return bclient.FuncLatencyClient(func() time.Duration {
		t0 := time.Now()
		_, err := conn.Write(buf)
		if err != nil {
			panic(err)
		}
		readPacket(conn)
		t1 := time.Now()
		if t1.Before(t0) {
			// Time went backwards (probably because somebody reset the clock - Go
			// doesn't yet support monotonic clocks). This test is obviously invalid.
			panic("time moved backwards; the results of this test are untrustworthy")
		}

		time.Sleep(pauseFlag)

		return t1.Sub(t0)
	}), nil
}

// server must be the TLS name of the server and a resolvable domain name.
func dial(cli *client.Client, server, port string) *tls.Conn {
	config := cli.Config.Clone()
	config.ServerName = server
	conn, err := tls.Dial("tcp", server+":"+port, config)
	if err != nil {
		panic(err)
	}
	return conn
}

func makeRSASignOp(params params.RSASignParams, op protocol.Operation) protocol.Operation {
	op.Opcode = params.Opcode
	op.Payload = randBytes(params.PayloadSize)
	return op
}

func makeECDSASignOp(params params.ECDSASignParams, op protocol.Operation) protocol.Operation {
	op.Opcode = params.Opcode
	op.Payload = randBytes(params.PayloadSize)
	return op
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic(err)
	}
	return b
}
