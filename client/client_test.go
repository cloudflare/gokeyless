package client

import "testing"

const (
	certFile = "testdata/rsa-client.pem"
	keyFile  = "testdata/rsa-client-key.pem"
	caFile   = "testdata/testca-keyserver.pem"
	server   = "rsa-server:3407"
)

func TestConnect(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	client, err := NewClient(certFile, keyFile, caFile)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := client.Dial(server)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := Ping(conn, []byte("Hello!")); err != nil {
		t.Fatal(err)
	}
}
