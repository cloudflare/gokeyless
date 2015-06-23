package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"log"
	"net"

	//"github.com/cloudflare/cf-tls/tls"
)

// Client is a Keyless Client capable of connecting to servers and performing keyless operations.
type Client struct {
	// Config is initialized with the client auth configuration used for communicating with keyless servers.
	Config *tls.Config
	Dialer *net.Dialer
	// OpenConns maps all known certificate digests to keyless server on which it can be found
	OpenConns map[string]net.Conn
}

// NewClient prepares a TLS client capable of connecting to keyservers.
func NewClient(certFile, keyFile, caFile string) (*Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	pemCerts, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}

	keyserverRoot := x509.NewCertPool()
	if !keyserverRoot.AppendCertsFromPEM(pemCerts) {
		return nil, errors.New("gokeyless/client: failed to read keyserver CA from PEM")
	}

	return &Client{
		Config: &tls.Config{
			RootCAs:      keyserverRoot,
			Certificates: []tls.Certificate{cert},
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		},
		Dialer:    &net.Dialer{},
		OpenConns: make(map[string]net.Conn),
	}, nil
}

// Dial retuns a (reused/reusable) connection to a keyless server.
func (c *Client) Dial(server string) (net.Conn, error) {
	if c.Config == nil {
		return nil, errors.New("gokeyless/client: TLS client has not yet been initialized with certificate and keyserver CA")
	}

	if conn, ok := c.OpenConns[server]; ok {
		return conn, nil
	}
	log.Printf("Dialing server: %s\n", server)
	conn, err := tls.Dial("tcp", server, c.Config)
	if err != nil {
		return nil, err
	}

	c.OpenConns[server] = conn
	return conn, err
}
