package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"regexp"

	"github.com/cloudflare/gokeyless/client"
)

var (
	server    string
	certFile  string
	keyFile   string
	caFile    string
	pubkeyDir string
	silent    bool
	pubkeyExt *regexp.Regexp
	loadSize  int
)

func init() {
	pubkeyExt = regexp.MustCompile(`.+\.pubkey`)
	flag.StringVar(&certFile, "cert", "client.pem", "Keyless server authentication certificate")
	flag.StringVar(&keyFile, "key", "client-key.pem", "Keyless server authentication key")
	flag.StringVar(&caFile, "ca-file", "keyserver-ca.pem", "Keyless client certificate authority")
	flag.StringVar(&pubkeyDir, "public-key-directory", "keys/", "Directory in which public keys are stored with .pubkey extension")
	flag.StringVar(&server, "server", "rsa-server:2407", "Keyless server on which to listen")
	flag.IntVar(&loadSize, "load", 256, "Number of concurrent connections to keyserver")
	flag.BoolVar(&silent, "silent", false, "Whether or not to output debugging information")
	flag.Parse()
}

func main() {
	var logOut io.Writer
	if silent {
		logOut = ioutil.Discard
	} else {
		logOut = os.Stdout
	}

	c, err := client.NewClientFromFile(certFile, keyFile, caFile, logOut)
	if err != nil {
		log.Fatal(err)
	}

	if err := testConnect(c, server); err != nil {
		log.Fatal(err)
	}

	pubkeys, err := LoadPubKeysFromDir(pubkeyDir)
	if err != nil {
		log.Fatal(err)
	}

	privkeys := make([]*client.PrivateKey, len(pubkeys))
	for i := range pubkeys {
		var err error
		privkeys[i], err = c.RegisterPublicKey(server, pubkeys[i])
		if err != nil {
			log.Fatal(err)
		}

		if err := testKey(privkeys[i]); err != nil {
			log.Fatal(err)
		}
	}

	log.Fatal(loadTest(func() error {
		if err := testConnect(c, server); err != nil {
			return err
		}

		for _, key := range privkeys {
			if err := testKey(key); err != nil {
				return err
			}
		}
		return nil
	}))
}

type testFunc func() error

func loadTest(test testFunc) error {
	errs := make(chan error)
	for i := 0; i < loadSize; i++ {
		go func() {
			for {
				errs <- test()
			}
		}()
	}
	for err := range errs {
		if err != nil {
			log.Println(err)
		}
	}
	return nil
}

// LoadPubKey attempts to load a public key from PEM or DER.
func LoadPubKey(in []byte) (priv crypto.PublicKey, err error) {
	p, rest := pem.Decode(in)
	if p != nil && len(rest) == 0 {
		in = p.Bytes
	}

	return x509.ParsePKIXPublicKey(in)
}

// LoadPubKeysFromDir reads all .pubkey files from a directory and returns associated PublicKey structs.
func LoadPubKeysFromDir(dir string) (pubkeys []crypto.PublicKey, err error) {
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && pubkeyExt.MatchString(info.Name()) {
			fmt.Printf("Loading %s...\n", path)
			in, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			priv, err := LoadPubKey(in)
			if err != nil {
				return err
			}

			pubkeys = append(pubkeys, priv)
		}
		return nil
	})
	return
}

func testConnect(c *client.Client, server string) error {
	conn, err := c.Dial(server)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Ping(nil)
}

func hashPtxt(h crypto.Hash, ptxt []byte) []byte {
	return h.New().Sum(ptxt)[len(ptxt):]
}

func testKey(key *client.PrivateKey) (err error) {
	ptxt := []byte("Hello!")
	r := rand.Reader
	hashes := []crypto.Hash{
		crypto.MD5SHA1,
		crypto.SHA1,
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
	}

	for _, h := range hashes {
		var msg, sig []byte
		if h == crypto.MD5SHA1 {
			msg = append(hashPtxt(crypto.MD5, ptxt), hashPtxt(crypto.SHA1, ptxt)...)
		} else {
			msg = hashPtxt(h, ptxt)
		}

		if sig, err = key.Sign(r, msg, h); err != nil {
			return
		}

		switch pub := key.Public().(type) {
		case *rsa.PublicKey:
			if err = rsa.VerifyPKCS1v15(pub, h, msg, sig); err != nil {
				return
			}
		case *ecdsa.PublicKey:
			ecdsaSig := new(struct{ R, S *big.Int })
			asn1.Unmarshal(sig, ecdsaSig)
			if !ecdsa.Verify(pub, msg, ecdsaSig.R, ecdsaSig.S) {
				return errors.New("ecdsa verify failed")
			}
		default:
			return errors.New("unknown public key type")
		}
	}

	if pub, ok := key.Public().(*rsa.PublicKey); ok {
		var c, m []byte
		if c, err = rsa.EncryptPKCS1v15(r, pub, ptxt); err != nil {
			return
		}

		if m, err = key.Decrypt(r, c, &rsa.PKCS1v15DecryptOptions{}); err != nil {
			return
		}
		if bytes.Compare(ptxt, m) != 0 {
			return errors.New("rsa decrypt failed")
		}

		if m, err = key.Decrypt(r, c, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: len(ptxt)}); err != nil {
			return
		}
		if bytes.Compare(ptxt, m) != 0 {
			return errors.New("rsa decrypt failed")
		}

		if m, err = key.Decrypt(r, c, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: len(ptxt) + 1}); err != nil {
			return
		}
		if bytes.Compare(ptxt, m) == 0 {
			return errors.New("rsa decrypt suceeded despite incorrect SessionKeyLen")
		}
	}

	return nil
}
