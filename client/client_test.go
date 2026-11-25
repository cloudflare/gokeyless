package client

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"go/parser"
	"go/token"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cloudflare/gokeyless/protocol"
)

func TestAddrSet(t *testing.T) {
	as := &AddrSet{}

	as.Add(&net.IPAddr{IP: net.IPv4(0, 0, 0, 0)}, 2407)
	as.Add(&net.IPAddr{IP: net.IPv4(1, 1, 1, 1)}, 2407)
	as.Add(&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)}, 2407)

	if !as.Contains(&net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 2407}) {
		t.Fatal("doesn't contain address that was added explicitly")
	}

	if as.Contains(&net.TCPAddr{IP: net.IPv4(2, 2, 2, 2), Port: 2407}) {
		t.Fatal("contains address that wasn't added")
	} else if as.Contains(&net.TCPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 2406}) {
		t.Fatal("contains address with port that wasn't added")
	} else if !as.Contains(&net.TCPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 2407}) {
		t.Fatal("doesn't contain address that was added explicitly")
	}

	if as.Contains(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2406}) {
		t.Fatal("contains address with port that wasn't added")
	} else if !as.Contains(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2407}) {
		t.Fatal("doesn't contain address in subnet")
	} else if !as.Contains(&net.TCPAddr{IP: net.IPv4(127, 2, 3, 4), Port: 2407}) {
		t.Fatal("doesn't contain address in subnet")
	}
}

// fakeMLDSAPub mimics an ML-DSA public key exposing its encoding via Bytes.
type fakeMLDSAPub []byte

func (f fakeMLDSAPub) Bytes() []byte { return f }

func TestSignOpFromSignerOpts(t *testing.T) {
	tests := []struct {
		name string
		pub  crypto.PublicKey
		opts crypto.SignerOpts
		want protocol.Op
	}{
		{"ecdsa sha256", &ecdsa.PublicKey{}, crypto.SHA256, protocol.OpECDSASignSHA256},
		{"rsa sha256", &rsa.PublicKey{}, crypto.SHA256, protocol.OpRSASignSHA256},
		{"rsa typed-nil pss", &rsa.PublicKey{}, (*rsa.PSSOptions)(nil), protocol.OpError},
		{"rsa typed-nil ed25519 opts", &rsa.PublicKey{}, (*ed25519.Options)(nil), protocol.OpError},
		{"ed25519", ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)), crypto.Hash(0), protocol.OpEd25519Sign},
		{"ed25519 nil opts", ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)), nil, protocol.OpError},
		{"ed25519 typed-nil opts", ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)), (*ed25519.Options)(nil), protocol.OpError},
		{"mldsa44", fakeMLDSAPub(make([]byte, 1312)), crypto.Hash(0), protocol.OpMLDSA44Sign},
		{"mldsa65", fakeMLDSAPub(make([]byte, 1952)), crypto.Hash(0), protocol.OpMLDSA65Sign},
		{"mldsa87", fakeMLDSAPub(make([]byte, 2592)), crypto.Hash(0), protocol.OpMLDSA87Sign},
		{"mldsa nil opts", fakeMLDSAPub(make([]byte, 1312)), nil, protocol.OpMLDSA44Sign},
		{"mldsa wrong size", fakeMLDSAPub(make([]byte, 1000)), crypto.Hash(0), protocol.OpError},
		{"mldsa with hash", fakeMLDSAPub(make([]byte, 1312)), crypto.SHA256, protocol.OpError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := signOpFromSignerOpts(&PrivateKey{public: tt.pub}, tt.opts); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewRemoteSignerWithCertUsage(t *testing.T) {
	pub := &ecdsa.PublicKey{}
	newSigner := func(cu protocol.CertUsage) (crypto.Signer, error) {
		return NewRemoteSignerWithCertUsage(context.Background(), nil, "", protocol.SKI{}, pub, "", nil, cu)
	}
	for _, cu := range []protocol.CertUsage{{Usage: 0xff, Scope: "svc"}, {Usage: protocol.CertUsageServiceServer}} {
		if _, err := newSigner(cu); err == nil {
			t.Errorf("expected error for cert usage %v", &cu)
		}
	}

	s, err := newSigner(protocol.CertUsage{Usage: protocol.CertUsageServiceServer, Scope: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.(*PrivateKey).certUsage; got == nil || got.Scope != "svc" {
		t.Fatalf("unexpected cert usage: %v", got)
	}
}

// TestClientDoesNotImportServer guards against client pulling in the server
// package, directly or through other in-module packages. Build tags are
// ignored, which over-approximates the import graph.
func TestClientDoesNotImportServer(t *testing.T) {
	const mod = "github.com/cloudflare/gokeyless"
	seen := map[string]bool{}
	var walk func(pkg string)
	walk = func(pkg string) {
		if seen[pkg] {
			return
		}
		seen[pkg] = true
		if pkg == mod+"/server" {
			t.Fatal("client transitively imports " + pkg)
		}
		dir := filepath.Join("..", strings.TrimPrefix(pkg, mod))
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no Go files for %s in %s: %v", pkg, dir, err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range af.Imports {
				if p, _ := strconv.Unquote(imp.Path.Value); p == mod || strings.HasPrefix(p, mod+"/") {
					walk(p)
				}
			}
		}
	}
	walk(mod + "/client")
}
