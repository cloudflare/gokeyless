package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/internal/protocol"
)

var keyExt = regexp.MustCompile(`.+\.key`)

const (
	UnixConnTimeout = time.Hour
	TCPConnTimeout  = time.Second * 30
)

// Keystore is an abstract container for a server's private keys, allowing
// lookup of keys based on incoming `Operation` requests.
type Keystore interface {
	Get(*protocol.Operation) (crypto.Signer, bool)
}

// NewDefaultKeystore returns a new default memory-based static keystore.
func NewDefaultKeystore() *DefaultKeystore {
	return &DefaultKeystore{
		skis: make(map[protocol.SKI]crypto.Signer),
	}
}

// DefaultKeystore is a simple in-memory key store.
type DefaultKeystore struct {
	sync.RWMutex
	skis map[protocol.SKI]crypto.Signer
}

// Add adds a new key to the server's internal repertoire.
// Stores in maps by SKI and (if possible) Digest, SNI, Server IP, and Client IP.
func (keys *DefaultKeystore) Add(op *protocol.Operation, priv crypto.Signer) error {
	ski, err := protocol.GetSKI(priv.Public())
	if err != nil {
		return err
	}

	keys.Lock()
	defer keys.Unlock()

	keys.skis[ski] = priv

	log.Debugf("add key with SKI: %02x", ski)
	return nil
}

// Get returns a key from keys, mapped from SKI.
func (keys *DefaultKeystore) Get(op *protocol.Operation) (crypto.Signer, bool) {
	keys.RLock()
	defer keys.RUnlock()

	ski := op.SKI
	if ski.Valid() {
		priv, found := keys.skis[ski]
		if found {
			log.Infof("fetch key with SKI: %s", ski)
			return priv, found
		}
	}

	log.Errorf("couldn't fetch key for %s.", op)
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
			log.Infof("loading %s...", path)

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
	// stats stores statistics about keyless requests.
	stats *statistics
	// GetCertificate is used for loading certificates.
	GetCertificate GetCertificate
	// Sealer is called for Seal and Unseal operations.
	Sealer Sealer

	// UnixListener is the listener serving unix://[UnixAddr]
	UnixListener net.Listener
	// TCPListener is the listener serving tcp://[Addr]
	TCPListener net.Listener

	// atomically loaded and stored to signal to readers to quit
	closed uint32
}

// GetCertificate is a function that returns a certificate given a request.
type GetCertificate func(op *protocol.Operation) (certChain []byte, err error)

// Sealer is an interface for an handler for OpSeal and OpUnseal. Seal and
// Unseal can return a protocol.Error to send a custom error code.
type Sealer interface {
	Seal(*protocol.Operation) ([]byte, error)
	Unseal(*protocol.Operation) ([]byte, error)
}

type req struct {
	conn   *tls.Conn
	mtx    *sync.Mutex
	packet *protocol.Packet
}

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
func NewServerFromFile(certFile, keyFile, caFile, addr, unixAddr string) (*Server, error) {
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
	return NewServer(cert, keylessCA, addr, unixAddr), nil
}

func (s *Server) handle(conn *tls.Conn, timeout time.Duration, ch chan req) {
	defer conn.Close()
	log.Debug("Handling new connection...")

	// This mutex is used by the workers to synchronize access to writing to
	// the connection. Since we're only reading from the connection, we don't
	// need it.
	var writeMtx sync.Mutex

	// Continuosly read request Packets from conn and respond
	// until a connection error (Read/Write failure) is encountered.
	var connError error
	for connError == nil {
		conn.SetDeadline(time.Now().Add(timeout))

		var h protocol.Packet
		if _, connError = h.ReadFrom(conn); connError != nil {
			break
		}

		if atomic.LoadUint32(&s.closed) == 1 {
			break
		}
		ch <- req{
			conn:   conn,
			mtx:    &writeMtx,
			packet: &h,
		}
	}

	if connError == io.EOF {
		log.Debug("connection closed by client")
	} else if err, ok := connError.(net.Error); ok && err.Timeout() {
		log.Debugf("server closes connection due to timeout: %v\n", err)
	} else {
		s.stats.logConnFailure()
		log.Errorf("connection error: %v\n", connError)
	}
}

func respond(conn *tls.Conn, mtx *sync.Mutex, id uint32, payload []byte) error {
	mtx.Lock()
	err := protocol.Respond(conn, id, payload)
	mtx.Unlock()
	return err
}

func respondPong(conn *tls.Conn, mtx *sync.Mutex, id uint32, payload []byte) error {
	mtx.Lock()
	err := protocol.RespondPong(conn, id, payload)
	mtx.Unlock()
	return err
}

func respondError(conn *tls.Conn, mtx *sync.Mutex, id uint32, err protocol.Error) error {
	mtx.Lock()
	e := protocol.RespondError(conn, id, err)
	mtx.Unlock()
	return e
}

func (s *Server) handleReqs(ch chan req) {
	runtime.LockOSThread()
	defer func() {
		if err := recover(); err != nil {
			log.Errorf("panic while handling request: %v", err)
			go s.handleReqs(ch)
		}
	}()

	var connError error
	for connError == nil {
		r, more := <-ch
		if !more {
			break
		}
		conn, mtx, h := r.conn, r.mtx, r.packet

		requestBegin := time.Now()
		log.Debugf("version:%d.%d id:%d body:%s", h.MajorVers, h.MinorVers, h.ID, h.Operation)

		var opts crypto.SignerOpts
		var key crypto.Signer
		var ok bool
		switch h.Operation.Opcode {
		case protocol.OpPing:
			connError = respondPong(conn, mtx, h.ID, h.Operation.Payload)
			s.stats.logRequestDuration(requestBegin)
			continue

		case protocol.OpGetCertificate:
			if s.GetCertificate == nil {
				log.Error("GetCertificate is nil")
				connError = respondError(conn, mtx, h.ID, protocol.ErrCertNotFound)
				s.stats.logInvalid(requestBegin)
				continue
			}

			certChain, err := s.GetCertificate(&h.Operation)
			if err != nil {
				log.Errorf("GetCertificate: %v", err)
				connError = respondError(conn, mtx, h.ID, protocol.ErrInternal)
				s.stats.logInvalid(requestBegin)
				continue
			}
			connError = respond(conn, mtx, h.ID, certChain)
			s.stats.logRequestDuration(requestBegin)
			continue

		case protocol.OpSeal, protocol.OpUnseal:
			if s.Sealer == nil {
				log.Error("Sealer is nil")
				connError = respondError(conn, mtx, h.ID, protocol.ErrInternal)
				s.stats.logInvalid(requestBegin)
				continue
			}

			var res []byte
			var err error
			if h.Operation.Opcode == protocol.OpSeal {
				res, err = s.Sealer.Seal(&h.Operation)
			} else {
				res, err = s.Sealer.Unseal(&h.Operation)
			}
			if err != nil {
				log.Errorf("Sealer: %v", err)
				code := protocol.ErrInternal
				if err, ok := err.(protocol.Error); ok {
					code = err
				}
				connError = respondError(conn, mtx, h.ID, code)
				s.stats.logInvalid(requestBegin)
				continue
			}
			connError = respond(conn, mtx, h.ID, res)
			s.stats.logRequestDuration(requestBegin)
			continue

		case protocol.OpRSADecrypt:
			if key, ok = s.Keys.Get(&h.Operation); !ok {
				log.Error(protocol.ErrKeyNotFound)
				connError = respondError(conn, mtx, h.ID, protocol.ErrKeyNotFound)
				s.stats.logInvalid(requestBegin)
				continue
			}

			if _, ok = key.Public().(*rsa.PublicKey); !ok {
				log.Errorf("%s: Key is not RSA\n", protocol.ErrCrypto)
				connError = respondError(conn, mtx, h.ID, protocol.ErrCrypto)
				s.stats.logInvalid(requestBegin)
				continue
			}

			rsaKey, ok := key.(crypto.Decrypter)
			if !ok {
				log.Errorf("%s: Key is not Decrypter\n", protocol.ErrCrypto)
				connError = respondError(conn, mtx, h.ID, protocol.ErrCrypto)
				s.stats.logInvalid(requestBegin)
				continue
			}

			ptxt, err := rsaKey.Decrypt(nil, h.Operation.Payload, nil)
			if err != nil {
				log.Errorf("%s: Decryption error: %v", protocol.ErrCrypto, err)
				connError = respondError(conn, mtx, h.ID, protocol.ErrCrypto)
				s.stats.logInvalid(requestBegin)
				continue
			}

			connError = respond(conn, mtx, h.ID, ptxt)
			s.stats.logRequestDuration(requestBegin)
			continue
		case protocol.OpRSASignMD5SHA1, protocol.OpECDSASignMD5SHA1:
			opts = crypto.MD5SHA1
		case protocol.OpRSASignSHA1, protocol.OpECDSASignSHA1:
			opts = crypto.SHA1
		case protocol.OpRSASignSHA224, protocol.OpECDSASignSHA224:
			opts = crypto.SHA224
		case protocol.OpRSASignSHA256, protocol.OpECDSASignSHA256, protocol.OpRSAPSSSignSHA256:
			opts = crypto.SHA256
		case protocol.OpRSASignSHA384, protocol.OpECDSASignSHA384, protocol.OpRSAPSSSignSHA384:
			opts = crypto.SHA384
		case protocol.OpRSASignSHA512, protocol.OpECDSASignSHA512, protocol.OpRSAPSSSignSHA512:
			opts = crypto.SHA512
		case protocol.OpPong, protocol.OpResponse, protocol.OpError:
			log.Errorf("%s: %s is not a valid request Opcode\n", protocol.ErrUnexpectedOpcode, h.Operation.Opcode)
			connError = respondError(conn, mtx, h.ID, protocol.ErrUnexpectedOpcode)
			s.stats.logInvalid(requestBegin)
			continue
		default:
			connError = respondError(conn, mtx, h.ID, protocol.ErrBadOpcode)
			s.stats.logInvalid(requestBegin)
			continue
		}

		switch h.Operation.Opcode {
		case protocol.OpRSAPSSSignSHA256, protocol.OpRSAPSSSignSHA384, protocol.OpRSAPSSSignSHA512:
			opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: opts.HashFunc()}
		}

		if key, ok = s.Keys.Get(&h.Operation); !ok {
			log.Error(protocol.ErrKeyNotFound)
			connError = respondError(conn, mtx, h.ID, protocol.ErrKeyNotFound)
			s.stats.logInvalid(requestBegin)
			continue
		}

		// Ensure we don't perform an ECDSA sign for an RSA request.
		switch h.Operation.Opcode {
		case protocol.OpRSASignMD5SHA1,
			protocol.OpRSASignSHA1,
			protocol.OpRSASignSHA224,
			protocol.OpRSASignSHA256,
			protocol.OpRSASignSHA384,
			protocol.OpRSASignSHA512,
			protocol.OpRSAPSSSignSHA256,
			protocol.OpRSAPSSSignSHA384,
			protocol.OpRSAPSSSignSHA512:
			if _, ok := key.Public().(*rsa.PublicKey); !ok {
				log.Errorf("%s: request is RSA, but key isn't\n", protocol.ErrCrypto)
				connError = respondError(conn, mtx, h.ID, protocol.ErrCrypto)
				s.stats.logInvalid(requestBegin)
				continue
			}
		}

		sig, err := key.Sign(rand.Reader, h.Operation.Payload, opts)
		if err != nil {
			log.Errorf("%s: Signing error: %v\n", protocol.ErrCrypto, err)
			connError = respondError(conn, mtx, h.ID, protocol.ErrCrypto)
			s.stats.logInvalid(requestBegin)
			continue
		}

		connError = respond(conn, mtx, h.ID, sig)
		s.stats.logRequestDuration(requestBegin)
	}
}

// Serve accepts incoming connections on the Listener l, creating a new service goroutine for each.
func (s *Server) Serve(l net.Listener, timeout time.Duration) error {
	defer l.Close()

	ch := make(chan req, 8)
	for i := 0; i < 8; i++ {
		go s.handleReqs(ch)
	}
	defer func() {
		atomic.StoreUint32(&s.closed, 1)
		close(ch)
	}()

	for {
		c, err := l.Accept()
		if err != nil {
			log.Error(err)
			return err
		}
		go s.handle(tls.Server(c, s.Config), timeout, ch)
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
	s.TCPListener = l

	log.Infof("Listening at tcp://%s\n", l.Addr())
	return s.Serve(l, TCPConnTimeout)
}

// UnixListenAndServe listens on the Unix socket address and handles keyless requests.
func (s *Server) UnixListenAndServe() error {
	if s.UnixAddr != "" {
		l, err := net.Listen("unix", s.UnixAddr)
		if err != nil {
			return err
		}
		s.UnixListener = l

		log.Infof("Listening at unix://%s\n", l.Addr())
		return s.Serve(l, UnixConnTimeout)
	}
	return errors.New("can't listen on empty path")
}

// Close shuts down the listeners.
func (s *Server) Close() {
	if s.UnixListener != nil {
		s.UnixListener.Close()
	}

	if s.TCPListener != nil {
		s.TCPListener.Close()
	}
}
