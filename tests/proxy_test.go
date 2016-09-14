package tests

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"testing"
	"time"

	"github.com/cloudflare/gokeyless/server"
)

const (
	tlsCert   = "testdata/server.pem"
	tlsKey    = "testdata/server-key.pem"
	caCert    = "testdata/ca.pem"
	network   = "tcp"
	localAddr = "localhost:7777"
)

func serverFunc(conn *tls.Conn) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	io.Copy(conn, conn)
}

func clientFunc(conn *tls.Conn) error {
	defer conn.Close()
	if !conn.ConnectionState().HandshakeComplete {
		return errors.New("handshake didn't complete")
	}

	input := []byte("Hello World!")
	if _, err := conn.Write(input); err != nil {
		return err
	}

	output, err := ioutil.ReadAll(conn)
	if err != nil {
		return err
	}
	if bytes.Compare(input, output) != 0 {
		return errors.New("input and output do not match")
	}
	return nil
}

// TestTLSProxy tests a real TLS keyless server which
// uses gokeyless client to finish TLS hanshake with a
// real TLS client.
func TestTLSProxy(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	cert, err := c.LoadTLSCertificate(serverAddr, tlsCert)
	if err != nil {
		t.Fatal(err)
	}
	c.RegisterCert(serverAddr, cert.Leaf)

	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   cert.Leaf.Subject.CommonName,
	}

	l, err := tls.Listen(network, localAddr, serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for c, err := l.Accept(); err == nil; c, err = l.Accept() {
			go serverFunc(c.(*tls.Conn))
		}
	}()

	// wait for server to start
	time.Sleep(100 * time.Millisecond)

	keys := server.NewDefaultKeystore()
	s.Keys = keys
	pemKey, err := ioutil.ReadFile(tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pem.Decode(pemKey)
	rsaKey, err := x509.ParseECPrivateKey(p.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Add(nil, rsaKey); err != nil {
		t.Fatal(err)
	}

	clientConfig := &tls.Config{
		ServerName: serverConfig.Certificates[0].Leaf.Subject.CommonName,
		RootCAs:    x509.NewCertPool(),
	}

	caBytes, err := ioutil.ReadFile(caCert)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig.RootCAs.AppendCertsFromPEM(caBytes)

	conn, err := tls.Dial(network, localAddr, clientConfig)
	if err != nil {
		t.Fatal(err)
	}

	if err = clientFunc(conn); err != nil {
		t.Fatal(err)
	}
}
