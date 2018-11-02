package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/protocol"
	"github.com/cloudflare/gokeyless/server/internal/client"
	buf_ecdsa "github.com/cloudflare/gokeyless/server/internal/ecdsa"
	textbook_rsa "github.com/cloudflare/gokeyless/server/internal/rsa"

	"golang.org/x/crypto/ed25519"
)

var keyExt = regexp.MustCompile(`.+\.key`)

// Keystore is an abstract container for a server's private keys, allowing
// lookup of keys based on incoming `Operation` requests.
type Keystore interface {
	// Get retreives a key for signing. The Sign method will be called directly on
	// this key, so it's advisable to perform any precomputation on this key that
	// may speed up signing over the course of multiple signatures (e.g.,
	// crypto/rsa.PrivateKey's Precompute method).
	Get(*protocol.Operation) (crypto.Signer, error)
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

// AddFromURI loads all keys matching the given PKCS#11 URI to the keystore. LoadURI
// is called to parse the URL, connect to the module, and populate a crypto.Signer,
// which is stored in the Keystore.
func (keys *DefaultKeystore) AddFromURI(uri string, LoadURI func(string) (crypto.Signer, error)) error {
	log.Infof("loading %s...", uri)

	priv, err := LoadURI(uri)
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

	log.Debugf("add signer with SKI: %v", ski)
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
func (keys *DefaultKeystore) Get(op *protocol.Operation) (crypto.Signer, error) {
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

// Server is a Keyless Server capable of performing opaque key operations.
type Server struct {
	config *ServeConfig
	// tlsConfig is initialized with the auth configuration used for communicating with keyless clients.
	tlsConfig *tls.Config
	// keys contains the private keys and certificates for the server.
	keys Keystore
	// stats stores statistics about keyless requests.
	stats *statistics
	// getCert is used for loading certificates.
	getCert GetCert
	// sealer is called for Seal and Unseal operations.
	sealer Sealer
	// dispatcher is an RPC server that exposes arbitrary APIs to the client.
	dispatcher *rpc.Server

	listeners []net.Listener
	wp        *workerPool
	mtx       sync.Mutex
	wg        sync.WaitGroup
}

// NewServer prepares a TLS server capable of receiving connections from keyless clients.
func NewServer(config *ServeConfig, cert tls.Certificate, keylessCA *x509.CertPool) *Server {
	if config == nil {
		config = DefaultServeConfig()
	}
	return &Server{
		config: config,
		tlsConfig: &tls.Config{
			ClientCAs:    keylessCA,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: []tls.Certificate{cert},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
		},
		keys:       NewDefaultKeystore(),
		stats:      newStatistics(),
		dispatcher: rpc.NewServer(),
	}
}

// NewServerFromFile reads certificate, key, and CA files in order to create a Server.
func NewServerFromFile(config *ServeConfig, certFile, keyFile, caFile string) (*Server, error) {
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
	return NewServer(config, cert, keylessCA), nil
}

// Config returns the Server's configuration.
func (s *Server) Config() *ServeConfig {
	return s.config
}

// TLSConfig returns the Server's TLS configuration.
func (s *Server) TLSConfig() *tls.Config {
	return s.tlsConfig
}

// SetKeystore sets the Keystore used by s. It is NOT safe to call concurrently
// with any other methods.
func (s *Server) SetKeystore(keys Keystore) {
	s.keys = keys
}

// SetSealer sets the Sealer used by s. It is NOT safe to call concurrently with
// any other methods.
func (s *Server) SetSealer(sealer Sealer) {
	s.sealer = sealer
}

// RegisterRPC publishes in the server the methods on rcvr.
//
// When a client sends a message with the opcode OpRPC, the payload of the
// message is extracted and decoded as an RPC method and a set of RPC arguments.
// This information is passed to the server's dispatcher (a *net/rpc.Server),
// which then calls the appropriate dynamically-registered reciever. See net/rpc
// for information on what kinds of recievers can be registered.
func (s *Server) RegisterRPC(rcvr interface{}) error {
	return s.dispatcher.Register(rcvr)
}

// GetCert is a function that returns a certificate given a request.
type GetCert func(op *protocol.Operation) (certChain []byte, err error)

// Sealer is an interface for an handler for OpSeal and OpUnseal. Seal and
// Unseal can return a protocol.Error to send a custom error code.
type Sealer interface {
	Seal(*protocol.Operation) ([]byte, error)
	Unseal(*protocol.Operation) ([]byte, error)
}

type request struct {
	pkt *protocol.Packet
	// time just after the request was deserialized from the connection
	reqBegin time.Time
	connName string
}

type response struct {
	id        uint32
	op        protocol.Operation
	reqOpcode protocol.Op
	err       protocol.Error
	// time just after the request was deserialized from the connection
	reqBegin time.Time
}

func (s *Server) makeRespondResponse(req request, payload []byte, requestBegin time.Time) response {
	s.stats.logRequestExecDuration(req.pkt.Opcode, requestBegin, protocol.ErrNone)
	return response{id: req.pkt.ID, op: protocol.MakeRespondOp(payload), reqOpcode: req.pkt.Opcode, err: protocol.ErrNone, reqBegin: req.reqBegin}
}

func (s *Server) makePongResponse(req request, payload []byte, requestBegin time.Time) response {
	s.stats.logRequestExecDuration(req.pkt.Opcode, requestBegin, protocol.ErrNone)
	return response{id: req.pkt.ID, op: protocol.MakePongOp(payload), reqOpcode: req.pkt.Opcode, err: protocol.ErrNone, reqBegin: req.reqBegin}
}

func (s *Server) makeErrResponse(req request, err protocol.Error, requestBegin time.Time) response {
	s.stats.logRequestExecDuration(req.pkt.Opcode, requestBegin, err)
	return response{id: req.pkt.ID, op: protocol.MakeErrorOp(err), reqOpcode: req.pkt.Opcode, err: err, reqBegin: req.reqBegin}
}

// otherWorker performs all non-ECDSA requests
type otherWorker struct {
	s    *Server
	name string
}

func newOtherWorker(s *Server, name string) *otherWorker {
	return &otherWorker{s: s, name: name}
}

func (w *otherWorker) Do(job interface{}) interface{} {
	w.s.stats.logDeqeueOtherRequest()

	req := job.(request)
	pkt := req.pkt

	log.Debugf("connection %s: worker=%v opcode=%s id=%d sni=%s ip=%s ski=%v",
		req.connName,
		w.name,
		pkt.Operation.Opcode,
		pkt.Header.ID,
		pkt.Operation.SNI,
		pkt.Operation.ServerIP,
		pkt.Operation.SKI)

	requestBegin := time.Now()
	var opts crypto.SignerOpts
	switch pkt.Operation.Opcode {
	case protocol.OpPing:
		return w.s.makePongResponse(req, pkt.Operation.Payload, requestBegin)

	case protocol.OpSeal, protocol.OpUnseal:
		if w.s.sealer == nil {
			log.Errorf("Worker %v: Sealer is nil", w.name)
			return w.s.makeErrResponse(req, protocol.ErrInternal, requestBegin)
		}

		var res []byte
		var err error
		if pkt.Operation.Opcode == protocol.OpSeal {
			res, err = w.s.sealer.Seal(&pkt.Operation)
		} else {
			res, err = w.s.sealer.Unseal(&pkt.Operation)
		}
		if err != nil {
			log.Errorf("Worker %v: Sealer: %v", w.name, err)
			code := protocol.ErrInternal
			if err, ok := err.(protocol.Error); ok {
				code = err
			}
			return w.s.makeErrResponse(req, code, requestBegin)
		}
		return w.s.makeRespondResponse(req, res, requestBegin)

	case protocol.OpRPC:
		codec := newServerCodec(pkt.Payload)

		err := w.s.dispatcher.ServeRequest(codec)
		if err != nil {
			log.Errorf("Worker %v: ServeRPC: %v", w.name, err)
			return w.s.makeErrResponse(req, protocol.ErrInternal, requestBegin)
		}
		return w.s.makeRespondResponse(req, codec.response, requestBegin)

	case protocol.OpEd25519Sign:
		keyLoadBegin := time.Now()
		key, err := w.s.keys.Get(&pkt.Operation)
		if err != nil {
			log.Errorf("failed to load key with sni=%s ip=%s ski=%v: %v", pkt.Operation.SNI, pkt.Operation.ServerIP, pkt.Operation.SKI, err)
			return w.s.makeErrResponse(req, protocol.ErrInternal, requestBegin)
		} else if key == nil {
			log.Errorf("failed to load key with sni=%s ip=%s ski=%v: %v", pkt.Operation.SNI, pkt.Operation.ServerIP, pkt.Operation.SKI, protocol.ErrKeyNotFound)
			return w.s.makeErrResponse(req, protocol.ErrKeyNotFound, requestBegin)
		}
		w.s.stats.logKeyLoadDuration(keyLoadBegin)

		if ed25519Key, ok := key.(ed25519.PrivateKey); ok {
			sig := ed25519.Sign(ed25519Key, pkt.Operation.Payload)
			return w.s.makeRespondResponse(req, sig, requestBegin)
		}

		sig, err := key.Sign(rand.Reader, pkt.Operation.Payload, crypto.Hash(0))
		if err != nil {
			log.Errorf("Worker %v: %s: Signing error: %v", w.name, protocol.ErrCrypto, err)
			return w.s.makeErrResponse(req, protocol.ErrCrypto, requestBegin)
		}
		return w.s.makeRespondResponse(req, sig, requestBegin)

	case protocol.OpRSADecrypt:
		keyLoadBegin := time.Now()
		key, err := w.s.keys.Get(&pkt.Operation)
		if err != nil {
			log.Errorf("failed to load key with sni=%s ip=%s ski=%v: %v", pkt.Operation.SNI, pkt.Operation.ServerIP, pkt.Operation.SKI, err)
			return w.s.makeErrResponse(req, protocol.ErrInternal, requestBegin)
		} else if key == nil {
			log.Errorf("failed to load key with sni=%s ip=%s ski=%v: %v", pkt.Operation.SNI, pkt.Operation.ServerIP, pkt.Operation.SKI, protocol.ErrKeyNotFound)
			return w.s.makeErrResponse(req, protocol.ErrKeyNotFound, requestBegin)
		}
		w.s.stats.logKeyLoadDuration(keyLoadBegin)

		if _, ok := key.Public().(*rsa.PublicKey); !ok {
			log.Errorf("Worker %v: %s: Key is not RSA", w.name, protocol.ErrCrypto)
			return w.s.makeErrResponse(req, protocol.ErrCrypto, requestBegin)
		}

		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			// Decrypt without removing padding; that's the client's responsibility.
			ptxt, err := textbook_rsa.Decrypt(rsaKey, pkt.Operation.Payload)
			if err != nil {
				log.Errorf("Worker %v: %v", w.name, err)
				return w.s.makeErrResponse(req, protocol.ErrCrypto, requestBegin)
			}
			return w.s.makeRespondResponse(req, ptxt, requestBegin)
		}

		rsaKey, ok := key.(crypto.Decrypter)
		if !ok {
			log.Errorf("Worker %v: %s: Key is not Decrypter", w.name, protocol.ErrCrypto)
			return w.s.makeErrResponse(req, protocol.ErrCrypto, requestBegin)
		}

		ptxt, err := rsaKey.Decrypt(nil, pkt.Operation.Payload, nil)
		if err != nil {
			log.Errorf("Worker %v: %s: Decryption error: %v", w.name, protocol.ErrCrypto, err)
			return w.s.makeErrResponse(req, protocol.ErrCrypto, requestBegin)
		}

		return w.s.makeRespondResponse(req, ptxt, requestBegin)

	case protocol.OpRSASignMD5SHA1:
		opts = crypto.MD5SHA1
	case protocol.OpRSASignSHA1:
		opts = crypto.SHA1
	case protocol.OpRSASignSHA224:
		opts = crypto.SHA224
	case protocol.OpRSASignSHA256, protocol.OpRSAPSSSignSHA256:
		opts = crypto.SHA256
	case protocol.OpRSASignSHA384, protocol.OpRSAPSSSignSHA384:
		opts = crypto.SHA384
	case protocol.OpRSASignSHA512, protocol.OpRSAPSSSignSHA512:
		opts = crypto.SHA512
	case protocol.OpPong, protocol.OpResponse, protocol.OpError:
		log.Errorf("Worker %v: %s: %s is not a valid request Opcode\n", w.name, protocol.ErrUnexpectedOpcode, pkt.Operation.Opcode)
		return w.s.makeErrResponse(req, protocol.ErrUnexpectedOpcode, requestBegin)
	default:
		return w.s.makeErrResponse(req, protocol.ErrBadOpcode, requestBegin)
	}

	switch pkt.Operation.Opcode {
	case protocol.OpRSAPSSSignSHA256, protocol.OpRSAPSSSignSHA384, protocol.OpRSAPSSSignSHA512:
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: opts.HashFunc()}
	}

	keyLoadBegin := time.Now()
	key, err := w.s.keys.Get(&pkt.Operation)
	if err != nil {
		log.Errorf("failed to load key with sni=%s ip=%s ski=%v: %v", pkt.Operation.SNI, pkt.Operation.ServerIP, pkt.Operation.SKI, err)
		return w.s.makeErrResponse(req, protocol.ErrInternal, requestBegin)
	} else if key == nil {
		log.Errorf("failed to load key with sni=%s ip=%s ski=%v: %v", pkt.Operation.SNI, pkt.Operation.ServerIP, pkt.Operation.SKI, protocol.ErrKeyNotFound)
		return w.s.makeErrResponse(req, protocol.ErrKeyNotFound, requestBegin)
	}
	w.s.stats.logKeyLoadDuration(keyLoadBegin)

	// Ensure we don't perform an RSA sign for an ECDSA request.
	if _, ok := key.Public().(*rsa.PublicKey); !ok {
		log.Errorf("Worker %v: %s: request is RSA, but key isn't\n", w.name, protocol.ErrCrypto)
		return w.s.makeErrResponse(req, protocol.ErrCrypto, requestBegin)
	}

	sig, err := key.Sign(rand.Reader, pkt.Operation.Payload, opts)
	if err != nil {
		log.Errorf("Worker %v: %s: Signing error: %v\n", w.name, protocol.ErrCrypto, err)
		return w.s.makeErrResponse(req, protocol.ErrCrypto, requestBegin)
	}

	return w.s.makeRespondResponse(req, sig, requestBegin)
}

type limitedWorker struct {
	s    *Server
	name string
}

func newLimitedWorker(s *Server, name string) *limitedWorker {
	return &limitedWorker{s: s, name: name}
}

func (w *limitedWorker) Do(job interface{}) interface{} {
	req := job.(request)
	pkt := req.pkt
	requestBegin := time.Now()
	log.Debugf("connection %s: worker=%v opcode=%s id=%d sni=%s ip=%s ski=%v",
		req.connName,
		w.name,
		pkt.Operation.Opcode,
		pkt.Header.ID,
		pkt.Operation.SNI,
		pkt.Operation.ServerIP,
		pkt.Operation.SKI)
	switch pkt.Operation.Opcode {
	case protocol.OpPing:
		return w.s.makePongResponse(req, pkt.Operation.Payload, requestBegin)
	case protocol.OpRPC:
		codec := newServerCodec(pkt.Payload)

		err := w.s.dispatcher.ServeRequest(codec)
		if err != nil {
			log.Errorf("Worker %v: ServeRPC: %v", w.name, err)
			return w.s.makeErrResponse(req, protocol.ErrInternal, requestBegin)
		}
		return w.s.makeRespondResponse(req, codec.response, requestBegin)
	default:
		return w.s.makeErrResponse(req, protocol.ErrBadOpcode, requestBegin)
	}
}

const randBufferLen = 1024

type ecdsaWorker struct {
	buf  *buf_ecdsa.SyncRandBuffer
	s    *Server
	name string
}

func newECDSAWorker(s *Server, buf *buf_ecdsa.SyncRandBuffer, name string) *ecdsaWorker {
	return &ecdsaWorker{
		buf:  buf,
		s:    s,
		name: name,
	}
}

func (w *ecdsaWorker) Do(job interface{}) interface{} {
	w.s.stats.logDeqeueECDSARequest()

	req := job.(request)
	pkt := req.pkt

	log.Debugf("connection %s: worker=%v opcode=%s id=%d sni=%s ip=%s ski=%v",
		req.connName,
		w.name,
		pkt.Operation.Opcode,
		pkt.Header.ID,
		pkt.Operation.SNI,
		pkt.Operation.ServerIP,
		pkt.Operation.SKI)

	requestBegin := time.Now()
	var opts crypto.SignerOpts
	switch pkt.Operation.Opcode {
	case protocol.OpECDSASignMD5SHA1:
		opts = crypto.MD5SHA1
	case protocol.OpECDSASignSHA1:
		opts = crypto.SHA1
	case protocol.OpECDSASignSHA224:
		opts = crypto.SHA224
	case protocol.OpECDSASignSHA256:
		opts = crypto.SHA256
	case protocol.OpECDSASignSHA384:
		opts = crypto.SHA384
	case protocol.OpECDSASignSHA512:
		opts = crypto.SHA512
	default:
		// It's the client's responsibility to send all non-ECDSA requests to the
		// pool of otherWorkers.
		panic(fmt.Sprintf("internal error: got unexpected opcode %v", pkt.Operation.Opcode))
	}

	keyLoadBegin := time.Now()
	key, err := w.s.keys.Get(&pkt.Operation)
	if err != nil {
		log.Errorf("failed to load key with sni=%s ip=%s ski=%v: %v", pkt.Operation.SNI, pkt.Operation.ServerIP, pkt.Operation.SKI, err)
		return w.s.makeErrResponse(req, protocol.ErrInternal, requestBegin)
	} else if key == nil {
		log.Errorf("failed to load key with sni=%s ip=%s ski=%v: %v", pkt.Operation.SNI, pkt.Operation.ServerIP, pkt.Operation.SKI, protocol.ErrKeyNotFound)
		return w.s.makeErrResponse(req, protocol.ErrKeyNotFound, requestBegin)
	}
	w.s.stats.logKeyLoadDuration(keyLoadBegin)

	// Ensure we don't perform an RSA sign for an ECDSA request.
	if _, ok := key.Public().(*ecdsa.PublicKey); !ok {
		log.Errorf("Worker %v: %s: request is ECDSA, but key isn't\n", w.name, protocol.ErrCrypto)
		return w.s.makeErrResponse(req, protocol.ErrCrypto, requestBegin)
	}

	var sig []byte
	if k, ok := key.(*ecdsa.PrivateKey); ok && k.Curve == elliptic.P256() {
		sig, err = buf_ecdsa.Sign(rand.Reader, k, pkt.Operation.Payload, opts, w.buf)
	} else {
		sig, err = key.Sign(rand.Reader, pkt.Operation.Payload, opts)
		log.Debugf("Worker %v: Computed ECDSA signature without buffer", w.name)
	}
	if err != nil {
		log.Errorf("Worker %v: %s: Signing error: %v\n", w.name, protocol.ErrCrypto, err)
		return w.s.makeErrResponse(req, protocol.ErrCrypto, requestBegin)
	}

	return w.s.makeRespondResponse(req, sig, requestBegin)
}

type randGenWorker struct {
	buf *buf_ecdsa.SyncRandBuffer
}

func newRandGenWorker(buf *buf_ecdsa.SyncRandBuffer) *randGenWorker {
	return &randGenWorker{buf: buf}
}

func (w *randGenWorker) Do(ctx context.Context) {
	err := w.buf.Fill(ctx, rand.Reader)
	if err != nil {
		panic(err)
	}
}

func (s *Server) addListener(l net.Listener) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if len(s.listeners) == 0 {
		if s.wp != nil {
			panic("workerPool exists without any listeners")
		}
		s.wp = newWorkerPool(s)
	}
	s.listeners = append(s.listeners, l)
	s.wg.Add(1)
}

func (s *Server) removeListener(l net.Listener) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	var listeners []net.Listener
	for i := range s.listeners {
		if s.listeners[i] != l {
			listeners = append(listeners, s.listeners[i])
		}
	}
	if len(listeners)+1 != len(s.listeners) {
		panic("attempt to remove listener which was not added")
	}
	if len(listeners) == 0 {
		s.wp.Destroy()
		s.wp = nil
	}
	s.listeners = listeners
	s.wg.Done()
}

// Serve accepts incoming connections on the Listener l, creating a new
// pair of service goroutines for each. The first time l.Accept returns a
// non-temporary error, everything will be torn down.
//
// If l is neither a TCP listener nor a Unix listener, then the timeout will be
// taken to be the lower of the TCP timeout and the Unix timeout specified in
// the server's config.
func (s *Server) Serve(l net.Listener) error {
	s.addListener(l)
	defer s.removeListener(l)
	defer l.Close()

	timeout := s.config.tcpTimeout
	switch l.(type) {
	case *net.TCPListener:
	case *net.UnixListener:
		timeout = s.config.unixTimeout
	default:
		if s.config.unixTimeout < timeout {
			timeout = s.config.unixTimeout
		}
	}

	// This map keeps track of all existing connections. This allows us to close
	// them all (and thus cause the associated goroutines to quit, freeing
	// resources) when we're about to return. The mutex protects the map since the
	// handle method concurrently deletes its connection from it once the
	// connection dies.
	var mapMtx sync.Mutex
	conns := make(map[*client.ConnHandle]bool)
	var wg sync.WaitGroup

	defer func() {
		// Close all of the connections so that the associated goroutines quit.
		mapMtx.Lock()
		for c := range conns {
			c.Destroy()
		}
		mapMtx.Unlock()
		// Wait for all of the goroutines to quit.
		wg.Wait()
	}()

	for {
		c, err := accept(l)
		if err != nil {
			log.Errorf("Accept error: %v; shutting down server", err)
			return err
		}

		tconn := tls.Server(c, s.tlsConfig) //If limited use just limited workers
		var conn *conn
		if s.config.IsLimited(tconn) {
			log.Debug("Connection is limited")
			conn = newConn(s, c.RemoteAddr().String(), tconn, timeout, s.wp.Limited, s.wp.Limited)
		} else {
			conn = newConn(s, c.RemoteAddr().String(), tconn, timeout, s.wp.ECDSA, s.wp.Other)
		}

		log.Debugf("connection %v: spawned", c.RemoteAddr())
		handle := client.SpawnConn(conn)

		mapMtx.Lock()
		conns[handle] = true
		mapMtx.Unlock()

		wg.Add(1)
		go func() {
			handle.Wait()
			log.Debugf("connection %v: removed", c.RemoteAddr())
			mapMtx.Lock()
			delete(conns, handle)
			mapMtx.Unlock()
			wg.Done()
		}()
	}
}

// accept wraps l.Accept with capped exponential-backoff in the case of
// temporary errors such as a lack of FDs.
func accept(l net.Listener) (net.Conn, error) {
	backoff := 5 * time.Millisecond
	for {
		c, err := l.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				log.Errorf("Accept error: %v; retrying in %v", err, backoff)
				time.Sleep(backoff)

				backoff = 2 * backoff
				if max := 10 * time.Second; backoff > max {
					backoff = max
				}

				continue
			}
			return nil, err
		}

		return c, nil
	}
}

// ListenAndServe listens on the TCP network address addr and then calls
// Serve to handle requests on incoming keyless connections.
func (s *Server) ListenAndServe(addr string) error {
	if addr != "" {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}

		log.Infof("Listening at tcp://%s\n", l.Addr())
		return s.Serve(l)
	}
	return errors.New("can't listen on empty address")
}

// UnixListenAndServe listens on the Unix socket address and handles
// keyless requests.
func (s *Server) UnixListenAndServe(path string) error {
	if path != "" {
		l, err := net.Listen("unix", path)
		if err != nil {
			return err
		}

		log.Infof("Listening at unix://%s\n", l.Addr())
		return s.Serve(l)
	}
	return errors.New("can't listen on empty path")
}

// Close shuts down the listeners.
func (s *Server) Close() {
	// Close each active listener. This will result in the blocking calls to
	// Accept to immediately return with error, which will trigger the teardown
	// of all active connections and associated goroutines.
	s.mtx.Lock()
	for _, l := range s.listeners {
		l.Close()
	}
	s.mtx.Unlock()

	// Block here until all goroutines have returned.
	s.wg.Wait()
}

// ServeConfig is used to configure a call to Server.Serve. It specifies the
// number of ECDSA worker goroutines, other worker goroutines, and background
// worker goroutines to use. It also specifies the network connection timeout.
type ServeConfig struct {
	ecdsaWorkers, otherWorkers int
	limitedWorkers             int
	bgWorkers                  int
	tcpTimeout, unixTimeout    time.Duration
	utilization                func(other, ecdsa float64)
	IsLimited                  func(conn *tls.Conn) bool
}

const (
	defaultTCPTimeout  = time.Second * 30
	defaultUnixTimeout = time.Hour
)

// DefaultServeConfig constructs a default ServeConfig with the following
// values:
//  - The number of ECDSA workers is max(2, runtime.NumCPU())
//  - The number of other workers is 2
//  - The number of background workers is 1
//  - The TCP connection timeout is 30 seconds
//  - The Unix connection timeout is 1 hour
func DefaultServeConfig() *ServeConfig {
	necdsa := runtime.NumCPU()
	if runtime.NumCPU() < 2 {
		necdsa = 2
	}
	return &ServeConfig{
		ecdsaWorkers:   necdsa,
		otherWorkers:   2,
		limitedWorkers: 2,
		bgWorkers:      1,
		tcpTimeout:     defaultTCPTimeout,
		unixTimeout:    defaultUnixTimeout,
		IsLimited:      func(conn *tls.Conn) bool { return false },
	}
}

// WithECDSAWorkers specifies the number of ECDSA worker goroutines to use.
func (s *ServeConfig) WithECDSAWorkers(n int) *ServeConfig {
	s.ecdsaWorkers = n
	return s
}

// ECDSAWorkers returns the number of ECDSA worker goroutines.
func (s *ServeConfig) ECDSAWorkers() int {
	return s.ecdsaWorkers
}

// WithOtherWorkers specifies the number of other worker goroutines to use.
func (s *ServeConfig) WithOtherWorkers(n int) *ServeConfig {
	s.otherWorkers = n
	return s
}

// OtherWorkers returns the number of other worker goroutines.
func (s *ServeConfig) OtherWorkers() int {
	return s.otherWorkers
}

// WithBackgroundWorkers specifies the number of background worker goroutines to
// use.
func (s *ServeConfig) WithBackgroundWorkers(n int) *ServeConfig {
	s.bgWorkers = n
	return s
}

// BackgroundWorkers returns the number of background worker goroutines.
func (s *ServeConfig) BackgroundWorkers() int {
	return s.bgWorkers
}

// WithTCPTimeout specifies the network connection timeout to use for TCP
// connections. This timeout is used when reading from or writing to established
// network connections.
func (s *ServeConfig) WithTCPTimeout(timeout time.Duration) *ServeConfig {
	s.tcpTimeout = timeout
	return s
}

// TCPTimeout returns the network connection timeout to use for TCP
// connections.
func (s *ServeConfig) TCPTimeout() time.Duration {
	return s.tcpTimeout
}

// WithUnixTimeout specifies the network connection timeout to use for Unix
// connections. This timeout is used when reading from or writing to established
// network connections.
func (s *ServeConfig) WithUnixTimeout(timeout time.Duration) *ServeConfig {
	s.unixTimeout = timeout
	return s
}

// UnixTimeout returns the network connection timeout to use for Unix
// connections.
func (s *ServeConfig) UnixTimeout() time.Duration {
	return s.unixTimeout
}

// WithUtilization specifies the function to call with periodic utilization
// information. On a fixed interval, the server will call f with the
// [0,1]-percentage of the server's other / ecdsa workers that are currently
// busy.
func (s *ServeConfig) WithUtilization(f func(other, ecdsa float64)) *ServeConfig {
	s.utilization = f
	return s
}

// serverCodec implements net/rpc.ServerCodec over the payload of a gokeyless
// operation. It can only be used one time.
type serverCodec struct {
	request  *gob.Decoder
	response []byte
}

func newServerCodec(payload []byte) *serverCodec {
	dec := gob.NewDecoder(bytes.NewBuffer(payload))
	return &serverCodec{request: dec}
}

func (sc *serverCodec) ReadRequestHeader(req *rpc.Request) error {
	return sc.request.Decode(req)
}

func (sc *serverCodec) ReadRequestBody(body interface{}) error {
	return sc.request.Decode(body)
}

func (sc *serverCodec) WriteResponse(res *rpc.Response, body interface{}) error {
	buff := &bytes.Buffer{}
	enc := gob.NewEncoder(buff)

	if err := enc.Encode(res); err != nil {
		return err
	} else if err := enc.Encode(body); err != nil {
		return err
	}

	sc.response = buff.Bytes()
	return nil
}

func (sc *serverCodec) Close() error {
	return errors.New("an rpc server codec cannot be closed")
}
