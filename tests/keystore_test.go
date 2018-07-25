package tests

import (
	"testing"

	"github.com/cloudflare/gokeyless/protocol"
	"github.com/cloudflare/gokeyless/server"
)

func TestDefaultKeyStoreAddRemove(t *testing.T) {
	ski, err := protocol.GetSKI(ed25519Key.Public())
	if err != nil {
		t.Fatal(err)
	}
	op := &protocol.Operation{SKI: ski}

	keys := server.NewDefaultKeystore()
	err = keys.AddFromFile(ed25519PrivKey, server.DefaultLoadKey)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := keys.Get(op)
	if err != nil {
		t.Fatal(err)
	} else if priv == nil {
		t.Fatalf("no key with SKI %s, expected a key", ski)
	}

	keys.Remove(ski)
	priv, err = keys.Get(op)
	if err != nil {
		t.Fatal(err)
	} else if priv != nil {
		t.Fatalf("got key with SKI %s, expected no key", ski)
	}
}
