package delegated

import (
	"crypto/tls"
	"github.com/cloudflare/gokeyless/protocol"
	"net"
	"net/rpc"
	"testing"
	"time"
)

// Test delegation as an RPC.
func TestDelegatorRPC(t *testing.T) {
	vers := VersionTLS13Draft28
	sigalg := uint16(tls.ECDSAWithP256AndSHA256)
	validTime := MaxTTL - time.Second

	// Set up the delegator state.
	cert := &testDelegationCert
	cfg := GetDefaultDelegatorConfig()
	cfg.Time = func() time.Time { return testNow }
	del, err := NewDelegator(cert, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Register the delegator as an RPC.
	err = rpc.Register(del)
	if err != nil {
		t.Fatal(err)
	}

	// Set up a TCP socket for the delegator.
	l, err := net.Listen("tcp", ":1234")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Listen for and serve a single connection.
	var serr error
	sch := make(chan net.Conn, 1)
	go func() {
		sconn, err := l.Accept()
		if err != nil {
			serr = err
			sch <- nil
			return
		}

		rpc.ServeConn(sconn)
		sch <- sconn
	}()

	// Dial the delegator.
	cli, err := rpc.Dial("tcp", "localhost:1234")
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	cred, _, err := NewCredential(sigalg, vers, validTime)
	if err != nil {
		t.Fatal(err)
	}

	credbytes, err := cred.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	var req DelegatorQuery
	req.SKI, _ = protocol.GetSKICert(testDelegationCert.Leaf)
	req.TTL = validTime
	req.Cred = credbytes
	// Perform the RPC.
	var resp []byte
	if err := cli.Call("Delegator.Sign", req, &resp); err != nil {
		t.Fatal(err)
	}

	dc, err := UnmarshalDelegatedCredential(resp)
	if err != nil {
		t.Fatal(err)
	}

	var ok bool
	if ok, err = dc.Validate(cert.Leaf, testNow); err != nil {
		t.Error(err)
	} else if !ok {
		t.Error("signature invalid, want valid")
	}

	// Try a request with an unsupported protocol version.
	req.Cred[4] ^= 0xff // Bytes 4:6 encode the signature scheme.
	if err = cli.Call("Delegator.Sign", req, &resp); err == nil {
		t.Error("request with unsupported signature scheme succeeds, want failure")
	} else {
		t.Log(err)
	}
	req.Cred[4] ^= 0xff

	// Try a request with an unsupported signature scheme.
	req.Cred[6] ^= 0xff // Bytes 6:8 encode the protocol version.
	if err = cli.Call("Delegator.Sign", req, &resp); err == nil {
		t.Error("request with bad protocol version succeeds, want failure")
	} else {
		t.Log(err)
	}
	req.Cred[6] ^= 0xff

	// Try a request with an invalid TTL.
	req.TTL = 2 * MaxTTL
	req.Cred, err = cred.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err = cli.Call("Delegator.Sign", req, &resp); err == nil {
		t.Error("request with invalid TTL succeeds, want failure")
	} else {
		t.Log(err)
	}
	cred.ValidTime = validTime

	cli.Close()

	// Wait for server to exit.
	srv := <-sch
	if srv == nil {
		t.Fatal(serr)
	}
}
