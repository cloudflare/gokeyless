package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
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
	buf_ecdsa "github.com/cloudflare/gokeyless/internal/server/internal/ecdsa"
	"github.com/cloudflare/gokeyless/internal/server/internal/fchan"
	"github.com/cloudflare/gokeyless/internal/server/internal/worker"
)

var keyExt = regexp.MustCompile(`.+\.key`)

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

type response struct {
	id uint32
	op protocol.Operation
}

func makeRespondResponse(id uint32, payload []byte) response {
	return response{id: id, op: protocol.MakeRespondOp(payload)}
}

func makePongResponse(id uint32, payload []byte) response {
	return response{id: id, op: protocol.MakePongOp(payload)}
}

func makeErrResponse(id uint32, err protocol.Error) response {
	return response{id: id, op: protocol.MakeErrorOp(err)}
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
	pkt := job.(*protocol.Packet)

	requestBegin := time.Now()
	log.Debugf("Worker %v: version:%d.%d id:%d body:%s", w.name, pkt.MajorVers, pkt.MinorVers, pkt.ID, pkt.Operation)

	var opts crypto.SignerOpts
	var key crypto.Signer
	var ok bool
	switch pkt.Operation.Opcode {
	case protocol.OpPing:
		w.s.stats.logRequestDuration(requestBegin)
		return makePongResponse(pkt.ID, pkt.Operation.Payload)

	case protocol.OpGetCertificate:
		if w.s.GetCertificate == nil {
			log.Errorf("Worker %v: GetCertificate is nil", w.name)
			w.s.stats.logInvalid(requestBegin)
			return makeErrResponse(pkt.ID, protocol.ErrCertNotFound)
		}

		certChain, err := w.s.GetCertificate(&pkt.Operation)
		if err != nil {
			log.Errorf("Worker %v: GetCertificate: %v", w.name, err)
			w.s.stats.logInvalid(requestBegin)
			return makeErrResponse(pkt.ID, protocol.ErrInternal)
		}
		w.s.stats.logRequestDuration(requestBegin)
		return makeRespondResponse(pkt.ID, certChain)

	case protocol.OpSeal, protocol.OpUnseal:
		if w.s.Sealer == nil {
			log.Errorf("Worker %v: Sealer is nil", w.name)
			w.s.stats.logInvalid(requestBegin)
			return makeErrResponse(pkt.ID, protocol.ErrInternal)
		}

		var res []byte
		var err error
		if pkt.Operation.Opcode == protocol.OpSeal {
			res, err = w.s.Sealer.Seal(&pkt.Operation)
		} else {
			res, err = w.s.Sealer.Unseal(&pkt.Operation)
		}
		if err != nil {
			log.Errorf("Worker %v: Sealer: %v", w.name, err)
			code := protocol.ErrInternal
			if err, ok := err.(protocol.Error); ok {
				code = err
			}
			w.s.stats.logInvalid(requestBegin)
			return makeErrResponse(pkt.ID, code)
		}
		w.s.stats.logRequestDuration(requestBegin)
		return makeRespondResponse(pkt.ID, res)

	case protocol.OpRSADecrypt:
		if key, ok = w.s.Keys.Get(&pkt.Operation); !ok {
			log.Error(protocol.ErrKeyNotFound)
			w.s.stats.logInvalid(requestBegin)
			return makeErrResponse(pkt.ID, protocol.ErrKeyNotFound)
		}

		if _, ok = key.Public().(*rsa.PublicKey); !ok {
			log.Errorf("Worker %v: %s: Key is not RSA", w.name, protocol.ErrCrypto)
			w.s.stats.logInvalid(requestBegin)
			return makeErrResponse(pkt.ID, protocol.ErrCrypto)
		}

		rsaKey, ok := key.(crypto.Decrypter)
		if !ok {
			log.Errorf("Worker %v: %s: Key is not Decrypter", w.name, protocol.ErrCrypto)
			w.s.stats.logInvalid(requestBegin)
			return makeErrResponse(pkt.ID, protocol.ErrCrypto)
		}

		ptxt, err := rsaKey.Decrypt(nil, pkt.Operation.Payload, nil)
		if err != nil {
			log.Errorf("Worker %v: %s: Decryption error: %v", w.name, protocol.ErrCrypto, err)
			w.s.stats.logInvalid(requestBegin)
			return makeErrResponse(pkt.ID, protocol.ErrCrypto)
		}

		w.s.stats.logRequestDuration(requestBegin)
		return makeRespondResponse(pkt.ID, ptxt)
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
		w.s.stats.logInvalid(requestBegin)
		return makeErrResponse(pkt.ID, protocol.ErrUnexpectedOpcode)
	default:
		w.s.stats.logInvalid(requestBegin)
		return makeErrResponse(pkt.ID, protocol.ErrBadOpcode)
	}

	switch pkt.Operation.Opcode {
	case protocol.OpRSAPSSSignSHA256, protocol.OpRSAPSSSignSHA384, protocol.OpRSAPSSSignSHA512:
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: opts.HashFunc()}
	}

	if key, ok = w.s.Keys.Get(&pkt.Operation); !ok {
		log.Error(protocol.ErrKeyNotFound)
		w.s.stats.logInvalid(requestBegin)
		return makeErrResponse(pkt.ID, protocol.ErrKeyNotFound)
	}

	// Ensure we don't perform an RSA sign for an ECDSA request.
	if _, ok := key.Public().(*rsa.PublicKey); !ok {
		log.Errorf("Worker %v: %s: request is RSA, but key isn't\n", w.name, protocol.ErrCrypto)
		w.s.stats.logInvalid(requestBegin)
		return makeErrResponse(pkt.ID, protocol.ErrCrypto)
	}

	sig, err := key.Sign(rand.Reader, pkt.Operation.Payload, opts)
	if err != nil {
		log.Errorf("Worker %v: %s: Signing error: %v\n", w.name, protocol.ErrCrypto, err)
		w.s.stats.logInvalid(requestBegin)
		return makeErrResponse(pkt.ID, protocol.ErrCrypto)
	}

	w.s.stats.logRequestDuration(requestBegin)
	return makeRespondResponse(pkt.ID, sig)
}

const randBufferLen = 1024 * 1024

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
	pkt := job.(*protocol.Packet)

	requestBegin := time.Now()
	log.Debugf("Worker %v: version:%d.%d id:%d body:%s", w.name, pkt.MajorVers, pkt.MinorVers, pkt.ID, pkt.Operation)

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

	if key, ok = w.s.Keys.Get(&pkt.Operation); !ok {
		log.Error(protocol.ErrKeyNotFound)
		w.s.stats.logInvalid(requestBegin)
		return makeErrResponse(pkt.ID, protocol.ErrKeyNotFound)
	}

	// Ensure we don't perform an RSA sign for an ECDSA request.
	if _, ok := key.Public().(*ecdsa.PublicKey); !ok {
		log.Errorf("Worker %v: %s: request is ECDSA, but key isn't\n", w.name, protocol.ErrCrypto)
		w.s.stats.logInvalid(requestBegin)
		return makeErrResponse(pkt.ID, protocol.ErrCrypto)
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
		w.s.stats.logInvalid(requestBegin)
		return makeErrResponse(pkt.ID, protocol.ErrCrypto)
	}

	w.s.stats.logRequestDuration(requestBegin)
	return makeRespondResponse(pkt.ID, sig)
}

type idler struct {
	buf *buf_ecdsa.SyncRandBuffer
}

func newIdler(buf *buf_ecdsa.SyncRandBuffer) *idler {
	return &idler{buf: buf}
}

func (i *idler) Idle() {
	err := i.buf.Fill(rand.Reader)
	if err != nil {
		panic(err)
	}
}

func (s *Server) handle(conn *tls.Conn, mtx *sync.Mutex, conns map[*tls.Conn]bool,
	otherPool, ecdsaPool *worker.Pool, timeout time.Duration) {

	log.Debug("Handling new connection:", conn)

	// NOTE: We use this custom channel because it is unbounded, and thus sends
	// will never block. This is required for correctness! If we used blocking
	// channels (like Go's native channels), then when the connection was killed
	// and the writer goroutine quit, there would be no way for the worker
	// goroutines to know. If there wasn't enough buffer space left in the
	// channel, they would fill it up with their responses and then block
	// indefinitely.
	//
	// Not only is this required for correctness when a connection dies, it is
	// also required to avoid a DoS risk. If the channel were bounded, an attacker
	// could simply submit a large number of jobs, but not read the responses off
	// the network. The network connection would eventually back up to the point
	// that the writer goroutine's call to write to the network connection would
	// block. At this point, the response channel would eventually fill up. At
	// that point, any worker goroutines attempting to send results would block
	// indefinitely. By continuing to send requests until every worker goroutine
	// was blocked, the attacker could completely freeze the server.
	//
	// Counterintuitively, using an unbounded channel is not a memory leak risk.
	// Values can only be sent on the channel after a job has been processed by a
	// worker, and the channel feeding jobs to the workers is itself bounded. That
	// bounded channel prevents jobs being submitted faster than the workers can
	// handle them, and also provides back pressure against the network connection
	// (since if the job submission channel is full, readaer goroutines will block
	// sending on that channel and will be unable to read from their network
	// connections; this backpressure will then propagate across the network to
	// the client).
	responses := fchan.NewUnbounded()

	var quit uint32
	commitFunc := func(resp interface{}) {
		// As an optimization, check to see whether the reader goroutine has
		// signaled that the connection has been closed. If it has, then the
		// response won't be sent back to the client anyway, so don't waste time
		// trying to write it to the channel.
		if atomic.LoadUint32(&quit) == 0 {
			responses.Send(resp)
		}
	}

	// Use a sync.Once so that only the first goroutine to encounter an error gets
	// to log it. This avoids the circumstance where a goroutine encounters an
	// error, logs it, and then closes the network connection, which causes the
	// other goroutine to also encounter an error (due to the closed connection)
	// and spuriously log it.
	//
	// We also use this to allow the reader goroutine to block the writer from
	// logging anything at all by calling doLogErr(nil). This is useful when the
	// reader wants to initiate a clean shutdown, and informs the writer of this
	// by closing the connection in order to get its wait calls to stop blocking.
	var logErr sync.Once
	doLogErr := func(err error) {
		logErr.Do(func() {
			if err == nil {
				// The reader called doLogErr just to beat the writer to the punch,
				// not to actually log an error.
				return
			} else if err == io.EOF {
				log.Debug("connection closed by client")
			} else if err, ok := err.(net.Error); ok && err.Timeout() {
				log.Debugf("closing connection due to timeout: %v\n", err)
			} else {
				s.stats.logConnFailure()
				log.Errorf("connection error: %v\n", err)
			}
		})
	}

	// Since all errors encountered will be encountered by both goroutines, we
	// put all error handling logic in the reader goroutine, keeping the writer
	// goroutine very simple. When an error is encountered, the reader will log
	// it, close the connection, and send a nil value on the responses channel.
	// If the writer is currently blocked in a call to write, that call will
	// return when the connection is closed. If the writer is currently blocked
	// reading from the responses channel, that call will return when the nil
	// value is sent. In either case, the writer will know to quit.

	var wg sync.WaitGroup
	wg.Add(2)

	// reader
	go func() {
		defer wg.Done()

		for {
			err := conn.SetReadDeadline(time.Now().Add(timeout))
			if err != nil {
				doLogErr(err)
				conn.Close()
				// Signal to any worker goroutines that they shouldn't bother writing
				// responses to the channel since they'll be discarded anyway.
				atomic.StoreUint32(&quit, 1)
				// Signal to the writer goroutine to quit.
				responses.Send(nil)
				return
			}

			pkt := new(protocol.Packet)
			_, err = pkt.ReadFrom(conn)
			if err != nil {
				doLogErr(err)
				conn.Close()
				// Signal to any worker goroutines that they shouldn't bother writing
				// responses to the channel since they'll be discarded anyway.
				atomic.StoreUint32(&quit, 1)
				// Signal to the writer goroutine to quit.
				responses.Send(nil)
				return
			}

			job := worker.NewJob(pkt, commitFunc)
			switch pkt.Operation.Opcode {
			case protocol.OpECDSASignMD5SHA1, protocol.OpECDSASignSHA1,
				protocol.OpECDSASignSHA224, protocol.OpECDSASignSHA256,
				protocol.OpECDSASignSHA384, protocol.OpECDSASignSHA512:
				ecdsaPool.SubmitJob(job)
			default:
				otherPool.SubmitJob(job)
			}
		}
	}()

	// writer
	go func() {
		defer wg.Done()
		pkt := protocol.Packet{
			Header: protocol.Header{
				MajorVers: 0x01,
				MinorVers: 0x00,
			},
		}

		for {
			val := responses.Receive()
			if val == nil {
				// The reader goroutine signaled for us to quit.
				return
			}
			resp := val.(response)

			pkt.Length = resp.op.Bytes()
			pkt.ID = resp.id
			pkt.Operation = resp.op
			buf, err := pkt.MarshalBinary()
			if err != nil {
				// According to MarshalBinary's documentation, it will never return a
				// non-nil error.
				panic(fmt.Sprintf("unexpected internal error: %v", err))
			}

			_, err = conn.Write(buf)
			if err != nil {
				doLogErr(err)
				conn.Close()
				return
			}
		}
	}()

	// Delete the connection from the map to avoid leaking resources.
	wg.Wait()
	mtx.Lock()
	delete(conns, conn)
	mtx.Unlock()
}

// Serve calls ServeConfig(l, DefaultServeConfig()).
func (s *Server) Serve(l net.Listener) error {
	return s.ServeConfig(l, DefaultServeConfig())
}

// ServeConfig accepts incoming connections on the Listener l, creating a new
// pair of service goroutines for each. The first time l.Accept fails,
// everything will be torn down.
func (s *Server) ServeConfig(l net.Listener, cfg *ServeConfig) error {
	defer l.Close()

	var others []worker.Worker
	var ecdsas []worker.Worker
	var idlers []worker.Idler
	rbuf := buf_ecdsa.NewSyncRandBuffer(randBufferLen, elliptic.P256())
	for i := 0; i < cfg.otherWorkers; i++ {
		others = append(others, newOtherWorker(s, fmt.Sprintf("other-%v", i)))
	}
	for i := 0; i < cfg.ecdsaWorkers; i++ {
		ecdsas = append(ecdsas, newECDSAWorker(s, rbuf, fmt.Sprintf("ecdsa-%v", i)))
	}
	for i := 0; i < cfg.idleWorkers; i++ {
		idlers = append(idlers, newIdler(rbuf))
	}

	idlepool := worker.NewIdlePool(idlers...)
	otherpool := worker.NewPool(others...)
	ecdsapool := worker.NewPool(ecdsas...)

	// This map keeps track of all existing connections. This allows us to close
	// them all (and thus cause the associated goroutines to quit, freeing
	// resources) when we're about to return. The mutex protects the map since the
	// handle method concurrently deletes its connection from it once the
	// connection dies.
	var mapMtx sync.Mutex
	conns := make(map[*tls.Conn]bool)
	var wg sync.WaitGroup

	defer func() {
		// Close all of the connections so that the associated goroutines quit.
		mapMtx.Lock()
		for c := range conns {
			c.Close()
		}
		mapMtx.Unlock()
		// Wait for all of the goroutines to quit.
		wg.Wait()

		// Destroy the pools
		idlepool.Destroy()
		otherpool.Destroy()
		ecdsapool.Destroy()
	}()

	for {
		c, err := l.Accept()
		if err != nil {
			log.Error(err)
			return err
		}

		tconn := tls.Server(c, s.Config)
		mapMtx.Lock()
		conns[tconn] = true
		mapMtx.Unlock()

		wg.Add(1)
		go func(tconn *tls.Conn, mtx *sync.Mutex, conns map[*tls.Conn]bool, otherpool, ecdsapool *worker.Pool, timeout time.Duration) {
			s.handle(tconn, mtx, conns, otherpool, ecdsapool, timeout)
			wg.Done()
		}(tconn, &mapMtx, conns, otherpool, ecdsapool, cfg.timeout)
	}
}

// ListenAndServe calls ListenAndServeConfig(DefaultServeConfig()).
func (s *Server) ListenAndServe() error {
	return s.ListenAndServeConfig(DefaultServeConfig())
}

// ListenAndServeConfig listens on the TCP network address s.Addr and then calls
// ServeConfig to handle requests on incoming keyless connections.
func (s *Server) ListenAndServeConfig(cfg *ServeConfig) error {
	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}

	s.Addr = l.Addr().String()
	s.TCPListener = l

	log.Infof("Listening at tcp://%s\n", l.Addr())
	return s.ServeConfig(l, cfg)
}

// UnixListenAndServe calls UnixListenAndServeConfig(DefaultServeConfig()).
func (s *Server) UnixListenAndServe() error {
	return s.UnixListenAndServeConfig(DefaultServeConfig())
}

// UnixListenAndServeConfig listens on the Unix socket address and handles
// keyless requests.
func (s *Server) UnixListenAndServeConfig(cfg *ServeConfig) error {
	if s.UnixAddr != "" {
		l, err := net.Listen("unix", s.UnixAddr)
		if err != nil {
			return err
		}
		s.UnixListener = l

		log.Infof("Listening at unix://%s\n", l.Addr())
		return s.ServeConfig(l, cfg)
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

// ServeConfig is used to configure a call to Server.Serve. It specifies the
// number of ECDSA worker goroutines, other worker goroutines, and idle worker
// goroutines to use. It also specifies the network connection timeout.
type ServeConfig struct {
	ecdsaWorkers, otherWorkers int
	idleWorkers                int
	timeout                    time.Duration
}

const defaultTimeout = time.Hour

// DefaultServeConfig constructs a default ServeConfig with the following
// values:
//  - The number of ECDSA workers is min(2, runtime.NumCPU())
//  - The number of other workers is 2
//  - The number of idle workers is 1
//  - The connection timeout is 1 hour
func DefaultServeConfig() *ServeConfig {
	necdsa := runtime.NumCPU()
	if runtime.NumCPU() < 2 {
		necdsa = 2
	}
	return &ServeConfig{
		ecdsaWorkers: necdsa,
		otherWorkers: 2,
		idleWorkers:  1,
		timeout:      defaultTimeout,
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

// IdleWorkers specifies the number of idle worker goroutines to use.
func (s *ServeConfig) IdleWorkers(n int) *ServeConfig {
	s.idleWorkers = n
	return s
}

// Timeout specifies the network connection timeout to use. This timeout is used
// when reading from or writing to established network connections.
func (s *ServeConfig) Timeout(timeout time.Duration) *ServeConfig {
	s.timeout = timeout
	return s
}
