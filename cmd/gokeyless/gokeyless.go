package main

import (
	"crypto"
	"flag"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/server"
)

var (
	port        string
	metricsPort string
	certFile    string
	keyFile     string
	caFile      string
	keyDir      string
	keyExt      *regexp.Regexp
)

func init() {
	keyExt = regexp.MustCompile(`.+\.key`)
	flag.StringVar(&certFile, "cert", "server.pem", "Keyless server authentication certificate")
	flag.StringVar(&keyFile, "key", "server-key.pem", "Keyless server authentication key")
	flag.StringVar(&caFile, "ca-file", "keyless-ca.pem", "Keyless client certificate authority")
	flag.StringVar(&keyDir, "private-key-directory", "keys/", "Directory in which private keys are stored with .key extension")
	flag.StringVar(&port, "port", "2407", "Keyless port on which to listen")
	flag.StringVar(&metricsPort, "metrics-port", "2408", "Port where the metrics API is served")
	flag.IntVar(&log.Level, "loglevel", 1, "Degree of logging")
	flag.Parse()
}

func main() {
	s, err := server.NewServerFromFile(certFile, keyFile, caFile,
		net.JoinHostPort("", port), net.JoinHostPort("", metricsPort))
	if err != nil {
		log.Fatal(err)
	}

	keys, err := LoadKeysFromDir(keyDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, key := range keys {
		if err := s.Keys.Add(nil, key); err != nil {
			log.Errorf("Unable to add key: %v", err)
		}
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

		if !info.IsDir() && keyExt.MatchString(info.Name()) {
			log.Debugf("Loading %s...\n", path)
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
