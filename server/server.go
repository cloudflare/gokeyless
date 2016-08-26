package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless"
)

var keyExt = regexp.MustCompile(`.+\.key`)

// Keystore is an abstract container for a server's private keys, allowing
// lookup of keys based on incoming `Operation` requests.
type Keystore interface {
	Get(*gokeyless.Operation) (crypto.Signer, bool)
}

// NewKeystore returns a new default memory-based static keystore.
func NewDefaultKeystore() *DefaultKeystore {
	return &DefaultKeystore{
		skis:      make(map[gokeyless.SKI]crypto.Signer),
		digests:   make(map[gokeyless.Digest]gokeyless.SKI),
		validAKIs: make(map[gokeyless.SKI]akiSet),
	}
}

// DefaultKeystore is a simple in-memory key store.
type DefaultKeystore struct {
	sync.RWMutex
	skis      map[gokeyless.SKI]crypto.Signer
	digests   map[gokeyless.Digest]gokeyless.SKI
	validAKIs map[gokeyless.SKI]akiSet
}

// Add adds a new key to the server's internal repertoire.
// Stores in maps by SKI and (if possible) Digest, SNI, Server IP, and Client IP.
func (keys *DefaultKeystore) Add(op *gokeyless.Operation, priv crypto.Signer) error {
	ski, err := gokeyless.GetSKI(priv.Public())
	if err != nil {
		return err
	}

	keys.Lock()
	defer keys.Unlock()

	if digest, err := gokeyless.GetDigest(priv.Public()); err == nil {
		keys.digests[digest] = ski
	}

	if op != nil {
		keys.validAKIs[ski] = keys.validAKIs[ski].Add(op.AKI)
	}

	keys.skis[ski] = priv

	log.Debugf("Adding key with SKI: %02x", ski)
	return nil
}

// Get returns a key from keys, mapped from SKI.
func (keys *DefaultKeystore) Get(op *gokeyless.Operation) (crypto.Signer, bool) {
	keys.RLock()
	defer keys.RUnlock()

	ski := op.SKI
	if ski.Valid() {
		priv, found := keys.skis[ski]
		if found {
			return priv, found
		}
	}

	log.Debug("Couldn't look up key based on SKI, trying Digest.")
	ski, ok := keys.digests[op.Digest]
	if ok {
		priv, found := keys.skis[ski]
		if found {
			return priv, found
		}
	}
	log.Infof("Couldn't look up key for %s.", op)
	return nil, false
}

// LoadKeysFromDir walks a directory, reads all ".key" files and calls LoadKey
// to parse the file into crypto.Signer for loading into the server Keystore.
func (keys *DefaultKeystore) LoadKeysFromDir(dir string, LoadKey func([]byte) (crypto.Signer, error)) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
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

			return keys.Add(nil, priv)
		}
		return nil
	})
}

type akiSet []gokeyless.SKI

func (akis akiSet) Contains(a gokeyless.SKI) bool {
	for _, aki := range akis {
		if aki.Equal(a) {
			return true
		}
	}
	return false
}

func (akis akiSet) Add(a gokeyless.SKI) akiSet {
	if akis.Contains(a) {
		return akis
	}
	return append(akis, a)
}

// Server is a Keyless Server capable of performing opaque key operations.
type Server struct {
	// TCP address to listen on
	Addr string
	// Unix socket to listen on
	UnixAddr string
	// Config is initialized with the auth configuration used for communicating with keyless clients.
	Config *tls.Config
	// Keys contains the private keys and certificates for the server.
	Keys Keystore
	// ActivationToken is the token used to prove an activating keyserver's identity.
	ActivationToken []byte
	// stats stores statistics about keyless requests.
	stats *statistics
	// GetCertificate is used for loading certificates.
	GetCertificate GetCertificate
}

// GetCertificate is a function that returns a certificate given a request.
type GetCertificate func(op *gokeyless.Operation) (certChain []byte, err error)

// NewServer prepares a TLS server capable of receiving connections from keyless clients.
func NewServer(cert tls.Certificate, keylessCA *x509.CertPool, addr, unixAddr string) *Server {
	return &Server{
		Addr:     addr,
		UnixAddr: unixAddr,
		Config: &tls.Config{
			ClientCAs:    keylessCA,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: []tls.Certificate{cert},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
		},
		Keys:  NewDefaultKeystore(),
		stats: newStatistics(),
	}
}

// NewServerFromFile reads certificate, key, and CA files in order to create a Server.
func NewServerFromFile(certFile, keyFile, caFile, addr, metricsAddr string) (*Server, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	pemCerts, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}

	keylessCA := x509.NewCertPool()
	if !keylessCA.AppendCertsFromPEM(pemCerts) {
		return nil, errors.New("gokeyless: failed to read keyless CA from PEM")
	}
	return NewServer(cert, keylessCA, addr, metricsAddr), nil
}

func (s *Server) handle(conn *gokeyless.Conn) {
	defer conn.Close()
	log.Debug("Handling new connection...")

	ch := make(chan *gokeyless.Header, 10)
	defer close(ch)
	for i := 0; i < 10; i++ {
		go s.handleReq(conn, ch)
	}

	// Continuosly read request Headers from conn and respond
	// until a connection error (Read/Write failure) is encountered.
	var connError error
	for connError == nil {
		conn.SetDeadline(time.Now().Add(time.Hour))

		var h *gokeyless.Header
		if h, connError = conn.ReadHeader(); connError != nil {
			s.stats.logConnFailure()
			continue
		}

		ch <- h
	}

	if connError == io.EOF {
		log.Debug("connection closed by client")
	} else {
		log.Errorf("connection error: %v\n", connError)
	}
}

func (s *Server) handleReq(conn *gokeyless.Conn, ch chan *gokeyless.Header) {
	var connError error
	for connError == nil {
		h := <-ch
		if h == nil {
			break
		}

		requestBegin := time.Now()
		log.Debugf("version:%d.%d id:%d body:%s", h.MajorVers, h.MinorVers, h.ID, h.Body)

		var opts crypto.SignerOpts
		var key crypto.Signer
		var ok bool
		switch h.Body.Opcode {
		case gokeyless.OpPing:
			connError = conn.RespondPong(h.ID, h.Body.Payload)
			s.stats.logRequest(requestBegin)
			continue

		case gokeyless.OpGetCertificate:
			if s.GetCertificate == nil {
				log.Error("GetCertificate is nil")
				connError = conn.RespondError(h.ID, gokeyless.ErrCertNotFound)
				continue
			} else {
				certChain, err := s.GetCertificate(h.Body)
				if err != nil {
					log.Errorf("GetCertificate: %v", err)
					connError = conn.RespondError(h.ID, gokeyless.ErrInternal)
					continue
				}
				connError = conn.Respond(h.ID, certChain)
			}

			continue

		case gokeyless.OpRSADecrypt:
			if key, ok = s.Keys.Get(h.Body); !ok {
				log.Error(gokeyless.ErrKeyNotFound)
				connError = conn.RespondError(h.ID, gokeyless.ErrKeyNotFound)
				s.stats.logInvalid(requestBegin)
				continue
			}

			if _, ok = key.Public().(*rsa.PublicKey); !ok {
				log.Errorf("%s: Key is not RSA\n", gokeyless.ErrCrypto)
				connError = conn.RespondError(h.ID, gokeyless.ErrCrypto)
				s.stats.logInvalid(requestBegin)
				continue
			}

			rsaKey, ok := key.(crypto.Decrypter)
			if !ok {
				log.Errorf("%s: Key is not Decrypter\n", gokeyless.ErrCrypto)
				connError = conn.RespondError(h.ID, gokeyless.ErrCrypto)
				s.stats.logInvalid(requestBegin)
				continue
			}

			ptxt, err := rsaKey.Decrypt(nil, h.Body.Payload, nil)
			if err != nil {
				log.Errorf("%s: Decryption error: %v", gokeyless.ErrCrypto, err)
				connError = conn.RespondError(h.ID, gokeyless.ErrCrypto)
				s.stats.logInvalid(requestBegin)
				continue
			}

			connError = conn.Respond(h.ID, ptxt)
			s.stats.logRequest(requestBegin)
			continue
		case gokeyless.OpRSASignMD5SHA1, gokeyless.OpECDSASignMD5SHA1:
			opts = crypto.MD5SHA1
		case gokeyless.OpRSASignSHA1, gokeyless.OpECDSASignSHA1:
			opts = crypto.SHA1
		case gokeyless.OpRSASignSHA224, gokeyless.OpECDSASignSHA224:
			opts = crypto.SHA224
		case gokeyless.OpRSASignSHA256, gokeyless.OpECDSASignSHA256, gokeyless.OpRSAPSSSignSHA256:
			opts = crypto.SHA256
		case gokeyless.OpRSASignSHA384, gokeyless.OpECDSASignSHA384, gokeyless.OpRSAPSSSignSHA384:
			opts = crypto.SHA384
		case gokeyless.OpRSASignSHA512, gokeyless.OpECDSASignSHA512, gokeyless.OpRSAPSSSignSHA512:
			opts = crypto.SHA512
		case gokeyless.OpActivate:
			if len(s.ActivationToken) > 0 {
				hashedToken := sha256.Sum256(s.ActivationToken)
				connError = conn.Respond(h.ID, hashedToken[:])
				s.stats.logRequest(requestBegin)
			} else {
				connError = conn.RespondError(h.ID, gokeyless.ErrBadOpcode)
				s.stats.logInvalid(requestBegin)
			}
			continue
		case gokeyless.OpPong, gokeyless.OpResponse, gokeyless.OpError:
			log.Errorf("%s: %s is not a valid request Opcode\n", gokeyless.ErrUnexpectedOpcode, h.Body.Opcode)
			connError = conn.RespondError(h.ID, gokeyless.ErrUnexpectedOpcode)
			s.stats.logInvalid(requestBegin)
			continue
		default:
			connError = conn.RespondError(h.ID, gokeyless.ErrBadOpcode)
			s.stats.logInvalid(requestBegin)
			continue
		}

		switch h.Body.Opcode {
		case gokeyless.OpRSAPSSSignSHA256, gokeyless.OpRSAPSSSignSHA384, gokeyless.OpRSAPSSSignSHA512:
			opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: opts.HashFunc()}
		}

		if key, ok = s.Keys.Get(h.Body); !ok {
			log.Error(gokeyless.ErrKeyNotFound)
			connError = conn.RespondError(h.ID, gokeyless.ErrKeyNotFound)
			s.stats.logInvalid(requestBegin)
			continue
		}

		// Ensure we don't perform an ECDSA sign for an RSA request.
		switch h.Body.Opcode {
		case gokeyless.OpRSASignMD5SHA1,
			gokeyless.OpRSASignSHA1,
			gokeyless.OpRSASignSHA224,
			gokeyless.OpRSASignSHA256,
			gokeyless.OpRSASignSHA384,
			gokeyless.OpRSASignSHA512,
			gokeyless.OpRSAPSSSignSHA256,
			gokeyless.OpRSAPSSSignSHA384,
			gokeyless.OpRSAPSSSignSHA512:
			if _, ok := key.Public().(*rsa.PublicKey); !ok {
				log.Errorf("%s: request is RSA, but key isn't\n", gokeyless.ErrCrypto)
				connError = conn.RespondError(h.ID, gokeyless.ErrCrypto)
				s.stats.logInvalid(requestBegin)
				continue
			}
		}

		sig, err := key.Sign(rand.Reader, h.Body.Payload, opts)
		if err != nil {
			log.Errorf("%s: Signing error: %v\n", gokeyless.ErrCrypto, err)
			connError = conn.RespondError(h.ID, gokeyless.ErrCrypto)
			s.stats.logInvalid(requestBegin)
			continue
		}

		connError = conn.Respond(h.ID, sig)
		s.stats.logRequest(requestBegin)
	}
}

// Serve accepts incoming connections on the Listener l, creating a new service goroutine for each.
func (s *Server) Serve(l net.Listener) error {
	defer l.Close()
	for {
		if c, err := l.Accept(); err != nil {
			log.Error(err)
		} else {
			go s.handle(gokeyless.NewConn(tls.Server(c, s.Config)))
		}
	}
}

// ListenAndServe listens on the TCP network address s.Addr and then
// calls Serve to handle requests on incoming keyless connections.
func (s *Server) ListenAndServe() error {
	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}

	s.Addr = l.Addr().String()
	log.Infof("Listening at tcp://%s\n", l.Addr())
	return s.Serve(l)
}

// UnixListenAndServe listens on the Unix socket address and handles keyless requests.
func (s *Server) UnixListenAndServe() error {
	if s.UnixAddr != "" {
		l, err := net.Listen("unix", s.UnixAddr)
		if err != nil {
			return err
		}

		log.Infof("Listening at unix://%s\n", l.Addr())
		return s.Serve(l)
	}
	return errors.New("can't listen on empty path")
}
