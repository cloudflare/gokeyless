package server

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/opentracing/opentracing-go"

	"github.com/cloudflare/gokeyless/internal/azure"
	"github.com/cloudflare/gokeyless/internal/google"
	"github.com/cloudflare/gokeyless/internal/rfc7512"
	"github.com/cloudflare/gokeyless/protocol"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
	log "github.com/sirupsen/logrus"
)

var keyExt = regexp.MustCompile(`.+\.key`)

// Keystore is an abstract container for a server's private keys, allowing
// lookup of keys based on incoming `Operation` requests.
type Keystore interface {
	// Get retrieves a key for signing. The Sign method will be called directly on
	// this key, so it's advisable to perform any precomputation on this key that
	// may speed up signing over the course of multiple signatures (e.g.,
	// crypto/rsa.PrivateKey's Precompute method).
	Get(context.Context, *protocol.Operation) (crypto.Signer, error)
}

// DefaultKeystore is a simple in-memory Keystore.
type DefaultKeystore struct {
	mtx  sync.RWMutex
	skis map[protocol.SKI]crypto.Signer
}

// NewDefaultKeystore returns a new DefaultKeystore.
func NewDefaultKeystore() *DefaultKeystore {
	return &DefaultKeystore{skis: make(map[protocol.SKI]crypto.Signer)}
}

// NewKeystoreFromDir creates a keystore populated from all of the ".key" files
// in dir. For each ".key" file, LoadKey is called to parse the file's contents
// into a crypto.Signer, which is stored in the Keystore.
func NewKeystoreFromDir(dir string, LoadKey func([]byte) (crypto.Signer, error)) (Keystore, error) {
	keys := NewDefaultKeystore()
	if err := keys.AddFromDir(dir, LoadKey); err != nil {
		return nil, err
	}
	return keys, nil
}

// AddFromDir adds all of the ".key" files in dir to the keystore. For each
// ".key" file, LoadKey is called to parse the file's contents into a
// crypto.Signer, which is stored in the Keystore.
func (keys *DefaultKeystore) AddFromDir(dir string, LoadKey func([]byte) (crypto.Signer, error)) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && keyExt.MatchString(info.Name()) {
			return keys.AddFromFile(path, LoadKey)
		}
		return nil
	})
}

// AddFromFile adds the key in the given file to the keystore. LoadKey is called
// to parse the file's contents into a crypto.Signer, which is stored in the
// Keystore.
func (keys *DefaultKeystore) AddFromFile(path string, LoadKey func([]byte) (crypto.Signer, error)) error {
	log.Infof("loading %s...", path)

	in, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	priv, err := LoadKey(in)
	if err != nil {
		return err
	}

	return keys.Add(nil, priv)
}

// AddFromURI loads all keys matching the given PKCS#11 or Azure URI to the keystore. LoadPKCS11URI
// is called to parse the URL, connect to the module, and populate a crypto.Signer,
// which is stored in the Keystore.
func (keys *DefaultKeystore) AddFromURI(uri string) error {
	log.Infof("loading %s...", uri)
	var priv crypto.Signer
	var err error
	if azure.IsKeyVaultURI(uri) {
		priv, err = azure.New(uri)
	} else if rfc7512.IsPKCS11URI(uri) {
		priv, err = loadPKCS11URI(uri)
	} else if google.IsKMSResource(uri) {
		priv, err = google.New(uri)
	} else {
		return fmt.Errorf("unknown uri format: %s", uri)
	}

	if err != nil {
		return err
	}
	return keys.Add(nil, priv)
}

// Add adds a new key to the server's internal store. Stores in maps by SKI and
// (if possible) Digest, SNI, Server IP, and Client IP.
func (keys *DefaultKeystore) Add(op *protocol.Operation, priv crypto.Signer) error {
	ski, err := protocol.GetSKI(priv.Public())
	if err != nil {
		return err
	}

	keys.mtx.Lock()
	defer keys.mtx.Unlock()

	keys.skis[ski] = priv

	log.Infof("add signer with SKI: %v (https://crt.sh/?ski=%v)", ski, ski)
	return nil
}

// DefaultLoadKey attempts to load a private key from PEM or DER.
func DefaultLoadKey(in []byte) (priv crypto.Signer, err error) {
	priv, err = helpers.ParsePrivateKeyPEM(in)
	if err == nil {
		return priv, nil
	}

	return derhelpers.ParsePrivateKeyDER(in)
}

// Get returns a key from keys, mapped from SKI.
func (keys *DefaultKeystore) Get(ctx context.Context, op *protocol.Operation) (crypto.Signer, error) {
	span, _ := opentracing.StartSpanFromContext(ctx, "DefaultKeystore.Get")
	defer span.Finish()

	keys.mtx.RLock()
	defer keys.mtx.RUnlock()

	ski := op.SKI
	if !ski.Valid() {
		return nil, fmt.Errorf("keyless: invalid SKI %s", ski)
	}
	priv, found := keys.skis[ski]
	if found {
		log.Infof("fetch key with SKI: %s", ski)
		return priv, nil
	}

	log.Infof("no key with SKI: %s", ski)
	return nil, nil
}
