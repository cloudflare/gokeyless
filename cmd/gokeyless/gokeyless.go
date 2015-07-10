package main

import (
	"crypto"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
	"github.com/cloudflare/gokeyless/server"
)

var (
	port     string
	certFile string
	keyFile  string
	caFile   string
	keyDir   string
	silent   bool
	keyName  *regexp.Regexp
)

func init() {
	keyName = regexp.MustCompile(`.+\.key`)
	flag.StringVar(&certFile, "cert", "server.pem", "Keyless server authentication certificate")
	flag.StringVar(&keyFile, "key", "server-key.pem", "Keyless server authentication key")
	flag.StringVar(&caFile, "ca-file", "keyless-ca.pem", "Keyless client certificate authority")
	flag.StringVar(&keyDir, "private-key-directory", "keys/", "Directory in which private keys are stored with .key extension")
	flag.StringVar(&port, "port", "2407", "Keyless port on which to listen")
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

	s, err := server.NewServerFromFile(certFile, keyFile, caFile, net.JoinHostPort("", port), logOut)
	if err != nil {
		log.Fatal(err)
	}

	keys, err := LoadKeysFromDir(keyDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, key := range keys {
		s.RegisterKey(key)
	}

	log.Fatal(s.ListenAndServe())
}

// LoadKey attempts to load a private key from PEM or DER.
func LoadKey(in []byte) (priv crypto.Signer, err error) {
	priv, err = helpers.ParsePrivateKeyPEM(in)
	if err == nil {
		return priv, nil
	}

	return derhelpers.ParsePrivateKeyDER(in)
}

// LoadKeysFromDir reads all .key files from a directory and returns
func LoadKeysFromDir(dir string) (keys []crypto.Signer, err error) {
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && keyName.MatchString(info.Name()) {
			fmt.Printf("Loading %s...\n", path)
			in, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			priv, err := LoadKey(in)
			if err != nil {
				return err
			}

			keys = append(keys, priv)
		}
		return nil
	})
	return
}
