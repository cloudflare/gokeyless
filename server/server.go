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
	"io"
	"io/ioutil"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/protocol"
	"github.com/cloudflare/gokeyless/server/internal/client"
	buf_ecdsa "github.com/cloudflare/gokeyless/server/internal/ecdsa"
	textbook_rsa "github.com/cloudflare/gokeyless/server/internal/rsa"
	"github.com/cloudflare/gokeyless/server/internal/worker"
)

var keyExt = regexp.MustCompile(`.+\.key`)

// Keystore is an abstract container for a server's private keys, allowing
// lookup of keys based on incoming `Operation` requests.
type Keystore interface {
	// Get retreives a key for signing. The Sign method will be called directly on
	// this key, so it's advisable to perform any precomputation on this key that
	// may speed up signing over the course of multiple signatures (e.g.,
	// crypto/rsa.PrivateKey's Precompute method).
	Get(*protocol.Operation) (crypto.Signer, bool)
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
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
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
	if err != nil {
		return nil, err
	}
	return keys, nil
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

	log.Debugf("add key with SKI: %v", ski)
	return nil
}

// Get returns a key from keys, mapped from SKI.
func (keys *DefaultKeystore) Get(op *protocol.Operation) (crypto.Signer, bool) {
	keys.mtx.RLock()
	defer keys.mtx.RUnlock()

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
}

type response struct {
	id        uint32
	op        protocol.Operation
	reqOpcode protocol.Op
	// time just after the request was deserialized from the connection
	reqBegin time.Time
}

func makeRespondResponse(req request, payload []byte) response {
	return response{id: req.pkt.ID, op: protocol.MakeRespondOp(payload), reqOpcode: req.pkt.Opcode, reqBegin: req.reqBegin}
}

func makePongResponse(req request, payload []byte) response {
	return response{id: req.pkt.ID, op: protocol.MakePongOp(payload), reqOpcode: req.pkt.Opcode, reqBegin: req.reqBegin}
}

func makeErrResponse(req request, err protocol.Error) response {
	return response{id: req.pkt.ID, op: protocol.MakeErrorOp(err), reqOpcode: req.pkt.Opcode, reqBegin: req.reqBegin}
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

	log.Debugf("Worker %v: version:%d.%d id:%d body:%s", w.name, pkt.MajorVers, pkt.MinorVers, pkt.ID, &pkt.Operation)

	requestBegin := time.Now()
	var opts crypto.SignerOpts
	var key crypto.Signer
	var ok bool
	switch pkt.Operation.Opcode {
	case protocol.OpPing:
		w.s.stats.logRequestExecDuration(pkt.Opcode, 0, requestBegin)
		return makePongResponse(req, pkt.Operation.Payload)

	case protocol.OpSeal, protocol.OpUnseal:
		if w.s.sealer == nil {
			log.Errorf("Worker %v: Sealer is nil", w.name)
			w.s.stats.logInvalid(pkt.Opcode)
			return makeErrResponse(req, protocol.ErrInternal)
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
			w.s.stats.logInvalid(pkt.Opcode)
			return makeErrResponse(req, code)
		}
		w.s.stats.logRequestExecDuration(pkt.Opcode, 0, requestBegin)
		return makeRespondResponse(req, res)

	case protocol.OpRPC:
		codec := newServerCodec(pkt.Payload)

		err := w.s.dispatcher.ServeRequest(codec)
		if err != nil {
			log.Errorf("Worker %v: ServeRPC: %v", w.name, err)
			w.s.stats.logInvalid(pkt.Opcode)
			return makeErrResponse(req, protocol.ErrInternal)
		}

		w.s.stats.logRequestExecDuration(pkt.Opcode, 0, requestBegin)
		return makeRespondResponse(req, codec.response)

	case protocol.OpRSADecrypt:
		keyLoadBegin := time.Now()
		if key, ok = w.s.keys.Get(&pkt.Operation); !ok {
			log.Error(protocol.ErrKeyNotFound)
			w.s.stats.logInvalid(pkt.Opcode)
			return makeErrResponse(req, protocol.ErrKeyNotFound)
		}
		w.s.stats.logKeyLoadDuration(keyLoadBegin)
		// Reset request beginning time; we don't want to have the request execution
		// duration include the duration to load the key.
		requestBegin = time.Now()

		if _, ok = key.Public().(*rsa.PublicKey); !ok {
			log.Errorf("Worker %v: %s: Key is not RSA", w.name, protocol.ErrCrypto)
			w.s.stats.logInvalid(pkt.Opcode)
			return makeErrResponse(req, protocol.ErrCrypto)
		}

		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			// Decrypt without removing padding; that's the client's responsibility.
			ptxt, err := textbook_rsa.Decrypt(rsaKey, pkt.Operation.Payload)
			if err != nil {
				log.Errorf("Worker %v: %v", w.name, err)
				w.s.stats.logInvalid(pkt.Opcode)
				return makeErrResponse(req, protocol.ErrCrypto)
			}
			w.s.stats.logRequestExecDuration(pkt.Opcode, len(rsaKey.Primes), requestBegin)
			return makeRespondResponse(req, ptxt)
		}

		rsaKey, ok := key.(crypto.Decrypter)
		if !ok {
			log.Errorf("Worker %v: %s: Key is not Decrypter", w.name, protocol.ErrCrypto)
			w.s.stats.logInvalid(pkt.Opcode)
			return makeErrResponse(req, protocol.ErrCrypto)
		}

		ptxt, err := rsaKey.Decrypt(nil, pkt.Operation.Payload, nil)
		if err != nil {
			log.Errorf("Worker %v: %s: Decryption error: %v", w.name, protocol.ErrCrypto, err)
			w.s.stats.logInvalid(pkt.Opcode)
			return makeErrResponse(req, protocol.ErrCrypto)
		}

		w.s.stats.logRequestExecDuration(pkt.Opcode, 0, requestBegin)
		return makeRespondResponse(req, ptxt)
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
		w.s.stats.logInvalid(pkt.Opcode)
		return makeErrResponse(req, protocol.ErrUnexpectedOpcode)
	default:
		w.s.stats.logInvalid(pkt.Opcode)
		return makeErrResponse(req, protocol.ErrBadOpcode)
	}

	switch pkt.Operation.Opcode {
	case protocol.OpRSAPSSSignSHA256, protocol.OpRSAPSSSignSHA384, protocol.OpRSAPSSSignSHA512:
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: opts.HashFunc()}
	}

	keyLoadBegin := time.Now()
	if key, ok = w.s.keys.Get(&pkt.Operation); !ok {
		log.Error(protocol.ErrKeyNotFound)
		w.s.stats.logInvalid(pkt.Opcode)
		return makeErrResponse(req, protocol.ErrKeyNotFound)
	}
	w.s.stats.logKeyLoadDuration(keyLoadBegin)
	// Reset request beginning time; we don't want to have the request execution
	// duration include the duration to load the key.
	requestBegin = time.Now()

	// Ensure we don't perform an RSA sign for an ECDSA request.
	if _, ok := key.Public().(*rsa.PublicKey); !ok {
		log.Errorf("Worker %v: %s: request is RSA, but key isn't\n", w.name, protocol.ErrCrypto)
		w.s.stats.logInvalid(pkt.Opcode)
		return makeErrResponse(req, protocol.ErrCrypto)
	}

	sig, err := key.Sign(rand.Reader, pkt.Operation.Payload, opts)
	if err != nil {
		log.Errorf("Worker %v: %s: Signing error: %v\n", w.name, protocol.ErrCrypto, err)
		w.s.stats.logInvalid(pkt.Opcode)
		return makeErrResponse(req, protocol.ErrCrypto)
	}

	primes := 0
	if k, ok := key.(*rsa.PrivateKey); ok {
		primes = len(k.Primes)
	}

	w.s.stats.logRequestExecDuration(pkt.Opcode, primes, requestBegin)
	return makeRespondResponse(req, sig)
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

	log.Debugf("Worker %v: version:%d.%d id:%d body:%s", w.name, pkt.MajorVers, pkt.MinorVers, pkt.ID, &pkt.Operation)

	var opts crypto.SignerOpts
	var key crypto.Signer
	var ok bool
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
	if key, ok = w.s.keys.Get(&pkt.Operation); !ok {
		log.Error(protocol.ErrKeyNotFound)
		w.s.stats.logInvalid(pkt.Opcode)
		return makeErrResponse(req, protocol.ErrKeyNotFound)
	}
	w.s.stats.logKeyLoadDuration(keyLoadBegin)

	// Start measuring the request execution duration here; we don't want to
	// include the duration to load the key.
	requestBegin := time.Now()

	// Ensure we don't perform an RSA sign for an ECDSA request.
	if _, ok := key.Public().(*ecdsa.PublicKey); !ok {
		log.Errorf("Worker %v: %s: request is ECDSA, but key isn't\n", w.name, protocol.ErrCrypto)
		w.s.stats.logInvalid(pkt.Opcode)
		return makeErrResponse(req, protocol.ErrCrypto)
	}

	var sig []byte
	var err error
	if k, ok := key.(*ecdsa.PrivateKey); ok && k.Curve == elliptic.P256() {
		sig, err = buf_ecdsa.Sign(rand.Reader, k, pkt.Operation.Payload, opts, w.buf)
	} else {
		sig, err = key.Sign(rand.Reader, pkt.Operation.Payload, opts)
		log.Debugf("Worker %v: Computed ECDSA signature without buffer", w.name)
	}
	if err != nil {
		log.Errorf("Worker %v: %s: Signing error: %v\n", w.name, protocol.ErrCrypto, err)
		w.s.stats.logInvalid(pkt.Opcode)
		return makeErrResponse(req, protocol.ErrCrypto)
	}

	w.s.stats.logRequestExecDuration(pkt.Opcode, 0, requestBegin)
	return makeRespondResponse(req, sig)
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

// conn implements the client.Conn interface. One is created to handle each
// connection from clients over the network. See the documentation in the client
// package for details.
type conn struct {
	conn net.Conn
	// name used to identify this client in logs
	name                 string
	timeout              time.Duration
	ecdsaPool, otherPool *worker.Pool
	// used by the LogConnErr method
	logErr sync.Once
	s      *Server

	closed uint32 // set to 1 when the conn is closed.
}

func newConn(s *Server, name string, c net.Conn, timeout time.Duration, ecdsa, other *worker.Pool) *conn {
	return &conn{conn: c, name: name, timeout: timeout, ecdsaPool: ecdsa, otherPool: other, s: s, closed: 0}
}

func (c *conn) GetJob() (job interface{}, pool *worker.Pool, ok bool) {
	err := c.conn.SetReadDeadline(time.Now().Add(c.timeout))
	if err != nil {
		// TODO: Is it possible for the client closing this half of the connection
		// to cause SetReadDeadline to return io.EOF? If so, we may want to do the
		// same logic as the other error handling block in this function.
		c.LogConnErr(err)
		c.conn.Close()
		atomic.StoreUint32(&c.closed, 1)
		return nil, nil, false
	}

	pkt := new(protocol.Packet)
	_, err = pkt.ReadFrom(c.conn)
	if err != nil {
		if err == io.EOF {
			// We can't rule out the possibility that the client just closed the
			// writing half of their connection (the reading half of ours), but still
			// wants to receive responses. Thus, we don't kill the connection.
			//
			// We also don't call c.Log because the writer goroutine could, in the
			// future, encounter an error that we legitimately want logged. Even if no
			// "real" error is encountered, when the other half of the connection is
			// closed, the writer goroutine will encounter EOF, and will log it, so
			// even if the connection is closed correctly, it will still get logged.
			log.Debugf("connection %v: reading half closed by client", c.name)
		} else {
			c.LogConnErr(err)
			c.conn.Close()
		}
		atomic.StoreUint32(&c.closed, 1)
		return nil, nil, false
	}

	c.s.stats.logRequest(pkt.Opcode)
	req := request{
		pkt:      pkt,
		reqBegin: time.Now(),
	}

	switch pkt.Operation.Opcode {
	case protocol.OpECDSASignMD5SHA1, protocol.OpECDSASignSHA1,
		protocol.OpECDSASignSHA224, protocol.OpECDSASignSHA256,
		protocol.OpECDSASignSHA384, protocol.OpECDSASignSHA512:
		c.s.stats.logEnqueueECDSARequest()
		return req, c.ecdsaPool, true
	default:
		c.s.stats.logEnqueueOtherRequest()
		return req, c.otherPool, true
	}
}

func (c *conn) SubmitResult(result interface{}) (ok bool) {
	resp := result.(response)
	pkt := protocol.Packet{
		Header: protocol.Header{
			MajorVers: 0x01,
			MinorVers: 0x00,
			Length:    resp.op.Bytes(),
			ID:        resp.id,
		},
		Operation: resp.op,
	}

	buf, err := pkt.MarshalBinary()
	if err != nil {
		// According to MarshalBinary's documentation, it will never return a
		// non-nil error.
		panic(fmt.Sprintf("unexpected internal error: %v", err))
	}

	if pkt.Opcode != protocol.OpError {
		// When there are errors, less code is often executed, and so these requests
		// are not representative of the time taken to execute a request.
		// Furthermore, we don't care nearly as much if they take a long time - we'd
		// prefer to get insight into how long successful requests are taking.
		c.s.stats.logRequestTotalDuration(resp.reqOpcode, resp.reqBegin)
	}

	_, err = c.conn.Write(buf)
	if err != nil {
		c.LogConnErr(err)
		c.conn.Close()
		atomic.StoreUint32(&c.closed, 1)
		return false
	}
	return true
}

func (c *conn) IsAlive() bool {
	return atomic.LoadUint32(&c.closed) == 0
}

func (c *conn) Destroy() {
	c.LogConnErr(nil)
	c.conn.Close()
	atomic.StoreUint32(&c.closed, 1)
}

// Log an error with the connection (reading, writing, setting a deadline, etc).
// Any error logged here is a fatal one that will cause us to terminate the
// connection and clean up the client.
func (c *conn) LogConnErr(err error) {
	// Use a sync.Once so that only the first goroutine to encounter an error gets
	// to log it. This avoids the circumstance where a goroutine encounters an
	// error, logs it, and then closes the network connection, which causes the
	// other goroutine to also encounter an error (due to the closed connection)
	// and spuriously log it.
	//
	// We also use this to allow Destroy to block the reader or writer from
	// logging anything at all by calling Log(nil).
	c.logErr.Do(func() {
		if err == nil {
			// Destroy was called, and it called Log to ensure that the errors
			// encountered by the reader and writer due to interacting with a closed
			// connection are not logged.
			log.Debugf("connection %v: server closing connection", c.name)
			return
		} else if err == io.EOF {
			log.Debugf("connection %v: closed by client", c.name)
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			log.Debugf("connection %v: closing due to timeout", c.name)
		} else {
			c.s.stats.logConnFailure()
			log.Errorf("connection %v: encountered error: %v", c.name, err)
		}
	})
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

		tconn := tls.Server(c, s.tlsConfig)
		conn := newConn(s, c.RemoteAddr().String(), tconn, timeout, s.wp.ECDSA, s.wp.Other)
		log.Debugf("spawning new connection: %v", c.RemoteAddr())
		handle := client.SpawnConn(conn)

		mapMtx.Lock()
		conns[handle] = true
		mapMtx.Unlock()

		wg.Add(1)
		go func() {
			handle.Wait()
			log.Debugf("connection %v removed", c.RemoteAddr())
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
	bgWorkers                  int
	tcpTimeout, unixTimeout    time.Duration
	utilization                func(other, ecdsa float64)
}

const (
	defaultTCPTimeout  = time.Second * 30
	defaultUnixTimeout = time.Hour
)

// DefaultServeConfig constructs a default ServeConfig with the following
// values:
//  - The number of ECDSA workers is min(2, runtime.NumCPU())
//  - The number of other workers is 2
//  - The number of background workers is 1
//  - The TCP connection timeout is 30 seconds
//  - The Unix connection timeout is 1 hour
//
// Note that the default ServeConfig does not specify an address for listening
// for TCP or Unix connections - at least one must be specified before using the
// ServeConfig.
func DefaultServeConfig() *ServeConfig {
	necdsa := runtime.NumCPU()
	if runtime.NumCPU() < 2 {
		necdsa = 2
	}
	return &ServeConfig{
		ecdsaWorkers: necdsa,
		otherWorkers: 2,
		bgWorkers:    1,
		tcpTimeout:   defaultTCPTimeout,
		unixTimeout:  defaultUnixTimeout,
	}
}

// ECDSAWorkers specifies the number of ECDSA worker goroutines to use.
func (s *ServeConfig) ECDSAWorkers(n int) *ServeConfig {
	s.ecdsaWorkers = n
	return s
}

// OtherWorkers specifies the number of other worker goroutines to use.
func (s *ServeConfig) OtherWorkers(n int) *ServeConfig {
	s.otherWorkers = n
	return s
}

// BackgroundWorkers specifies the number of background worker goroutines to
// use.
func (s *ServeConfig) BackgroundWorkers(n int) *ServeConfig {
	s.bgWorkers = n
	return s
}

// TCPTimeout specifies the network connection timeout to use for TCP
// connections. This timeout is used when reading from or writing to established
// network connections.
func (s *ServeConfig) TCPTimeout(timeout time.Duration) *ServeConfig {
	s.tcpTimeout = timeout
	return s
}

// UnixTimeout specifies the network connection timeout to use for Unix
// connections. This timeout is used when reading from or writing to established
// network connections.
func (s *ServeConfig) UnixTimeout(timeout time.Duration) *ServeConfig {
	s.unixTimeout = timeout
	return s
}

// Utilization specifies the function to call with periodic utilization
// information. On a fixed interval, the server will call f with the
// [0,1]-percentage of the server's other / ecdsa workers that are currently
// busy.
func (s *ServeConfig) Utilization(f func(other, ecdsa float64)) *ServeConfig {
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
