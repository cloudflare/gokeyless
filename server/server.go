package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
	"net/rpc"
	"os"
	"sync"
	"time"

	"github.com/cloudflare/gokeyless/certmetrics"
	"github.com/cloudflare/gokeyless/tracing"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/sync/semaphore"

	"github.com/cloudflare/gokeyless/protocol"
	textbook_rsa "github.com/cloudflare/gokeyless/server/internal/rsa"

	log "github.com/sirupsen/logrus"
)

// Server is a Keyless Server capable of performing opaque key operations.
type Server struct {
	config *ServeConfig
	// tlsConfig is initialized with the auth configuration used for communicating with keyless clients.
	tlsConfig *tls.Config
	// keys contains the private keys and certificates for the server.
	keys Keystore
	// getCert is used for loading certificates.
	getCert GetCert
	// sealer is called for Seal and Unseal operations.
	sealer Sealer
	// dispatcher is an RPC server that exposes arbitrary APIs to the client.
	dispatcher *rpc.Server
	// limitedDispatcher is an RPC server for APIs less trusted clients can be trusted with
	limitedDispatcher *rpc.Server

	listeners map[net.Listener]map[net.Conn]struct{}
	shutdown  bool
	mtx       sync.Mutex
}

// NewServer prepares a TLS server capable of receiving connections from keyless clients.
func NewServer(config *ServeConfig, cert tls.Certificate, keylessCA *x509.CertPool) (*Server, error) {
	if config == nil {
		config = DefaultServeConfig()
	}
	s := &Server{
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
		keys:              NewDefaultKeystore(),
		dispatcher:        rpc.NewServer(),
		limitedDispatcher: rpc.NewServer(),
		listeners:         make(map[net.Listener]map[net.Conn]struct{}),
	}

	return s, nil
}

// NewServerFromFile reads certificate, key, and CA files in order to create a Server.
func NewServerFromFile(config *ServeConfig, certFile, keyFile, caFile string) (*Server, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	pemCerts, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}

	keylessCA := x509.NewCertPool()
	if !keylessCA.AppendCertsFromPEM(pemCerts) {
		return nil, errors.New("gokeyless: failed to read keyless CA from PEM")
	}
	return NewServer(config, cert, keylessCA)
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
// which then calls the appropriate dynamically-registered receiver. See net/rpc
// for information on what kinds of receivers can be registered.
func (s *Server) RegisterRPC(rcvr interface{}) error {
	return s.dispatcher.Register(rcvr)
}

// RegisterLimitedRPC makes RPCs available for limited clients.
func (s *Server) RegisterLimitedRPC(rcvr interface{}) error {
	return s.limitedDispatcher.Register(rcvr)
}

// GetCert is a function that returns a certificate given a request.
type GetCert func(op *protocol.Operation) (certChain []byte, err error)

// Sealer is an interface for an handler for OpSeal and OpUnseal. Seal and
// Unseal can return a protocol.Error to send a custom error code.
type Sealer interface {
	Seal(*protocol.Operation) ([]byte, error)
	Unseal(*protocol.Operation) ([]byte, error)
}

// handler is associated with a connection and contains bookkeeping
// information used across goroutines. The channel tokens limits the
// concurrency: before reading a request a token is extracted, when
// writing the response a token is returned.
type handler struct {
	name     string
	s        *Server
	tokens   *semaphore.Weighted
	mtx      sync.Mutex
	limited  bool
	listener net.Listener
	conn     net.Conn
	timeout  time.Duration
	closed   bool
}

func (h *handler) close() {
	if !h.closed {
		h.conn.Close() // ignoring error: what can we do?
		h.s.mtx.Lock()
		delete(h.s.listeners[h.listener], h.conn)
		h.s.mtx.Unlock()
		logConnFailure()
		h.closed = true
	}
}

func (h *handler) closeWithWritingErr(err error) {
	if !h.closed {
		log.Errorf("connection %v: error in writing response %v", h.name, err)
		h.close()
	}
}

func (h *handler) handle(ctx context.Context, pkt *protocol.Packet, reqTime time.Time) {

	spanCtx, err := tracing.SpanContextFromBinary(pkt.Operation.JaegerSpan)
	if err != nil {
		log.Errorf("failed to extract span: %v", err)
	}
	span, ctx := opentracing.StartSpanFromContext(ctx, "handler.handle", ext.RPCServerOption(spanCtx))
	defer span.Finish()
	tracing.SetOperationSpanTags(span, &pkt.Operation)
	span.SetTag("connection", h.name)

	var resp response
	start := time.Now()
	logRequest(pkt.Opcode)
	if h.limited {
		resp = h.s.limitedDo(ctx, pkt, h.name)
	} else {
		resp = h.s.unlimitedDo(ctx, pkt, h.name)
	}
	logRequestExecDuration(ctx, pkt.Operation.Opcode, start, resp.op.ErrorVal())
	respPkt := protocol.Packet{
		Header: protocol.Header{
			MajorVers: 0x01,
			MinorVers: 0x00,
			Length:    resp.op.Bytes(),
			ID:        resp.id,
		},
		Operation: resp.op,
	}
	h.tokens.Release(1)
	h.mtx.Lock()
	defer h.mtx.Unlock()
	defer logRequestTotalDuration(ctx, pkt.Operation.Opcode, reqTime, resp.op.ErrorVal())
	err = h.conn.SetWriteDeadline(time.Now().Add(h.timeout))
	if err != nil {
		h.closeWithWritingErr(err)
		return
	}
	_, err = respPkt.WriteTo(h.conn)
	if err != nil {
		h.closeWithWritingErr(err)
	}
}

func (h *handler) loop() error {
	var err error
	for {
		pkt := new(protocol.Packet)
		ctx := context.Background()
		err = h.tokens.Acquire(ctx, 1)
		if err != nil {
			break
		}
		err = h.conn.SetReadDeadline(time.Now().Add(h.timeout))
		if err != nil {
			h.tokens.Release(1)
			break
		}
		_, err = pkt.ReadFrom(h.conn)
		if err != nil {
			h.tokens.Release(1)
			break
		}
		go h.handle(ctx, pkt, time.Now())
	}
	var neterr net.Error
	ok := errors.As(err, &neterr)
	// unless there was a timeout, return on any error
	if !ok || !neterr.Timeout() {
		// an EOF possibly means the other end ungracefully closed, so log as debug
		msg := fmt.Sprintf("closing connection %v: read error %s", h.name, err)
		if errors.Is(err, io.EOF) {
			log.Debug(msg)
		} else {
			log.Error(msg)
		}
		h.mtx.Lock()
		defer h.mtx.Unlock()
		h.close()
		return err
	}
	// In the event of a read timeout, gracefully close
	ctx, end := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
	defer end()
	h.tokens.Acquire(ctx, int64(h.s.config.maxConnPendingRequests))
	h.mtx.Lock()
	defer h.mtx.Unlock()
	h.close()
	return err
}

type response struct {
	id uint32
	op protocol.Operation
}

func makeRespondResponse(pkt *protocol.Packet, payload []byte) response {
	return response{id: pkt.ID, op: protocol.MakeRespondOp(payload)}
}

func makePongResponse(pkt *protocol.Packet, payload []byte) response {
	return response{id: pkt.ID, op: protocol.MakePongOp(payload)}
}

func makeErrResponse(pkt *protocol.Packet, err protocol.Error) response {
	return response{id: pkt.ID, op: protocol.MakeErrorOp(err)}
}

func (s *Server) unlimitedDo(ctx context.Context, pkt *protocol.Packet, connName string) response {
	span, ctx := opentracing.StartSpanFromContext(ctx, "server.unlimitedDo")
	defer span.Finish()
	log.Debugf("connection %s: limited=false  opcode=%s id=%d sni=%s ip=%s ski=%v",
		connName,
		pkt.Operation.Opcode,
		pkt.Header.ID,
		pkt.Operation.SNI,
		pkt.Operation.ServerIP,
		pkt.Operation.SKI)

	var opts crypto.SignerOpts
	switch pkt.Operation.Opcode {
	case protocol.OpPing:
		return makePongResponse(pkt, pkt.Operation.Payload)

	case protocol.OpSeal, protocol.OpUnseal:
		if s.sealer == nil {
			log.Errorf("Sealer is nil")
			return makeErrResponse(pkt, protocol.ErrInternal)
		}

		var res []byte
		var err error
		if pkt.Operation.Opcode == protocol.OpSeal {
			res, err = s.sealer.Seal(&pkt.Operation)
		} else {
			res, err = s.sealer.Unseal(&pkt.Operation)
		}
		if err != nil {
			log.Errorf("Connection %s: Sealer: %v", connName, err)
			code := protocol.ErrInternal
			if err, ok := err.(protocol.Error); ok {
				code = err
			}
			return makeErrResponse(pkt, code)
		}
		return makeRespondResponse(pkt, res)

	case protocol.OpRPC:
		codec := newServerCodec(pkt.Payload)

		err := s.dispatcher.ServeRequest(codec)
		if err != nil {
			log.Errorf("Connection %s: ServeRPC: %v", connName, err)
			return makeErrResponse(pkt, protocol.ErrInternal)
		}
		return makeRespondResponse(pkt, codec.response)

	case protocol.OpCustom:
		customOpFunc := s.config.CustomOpFunc()
		if customOpFunc == nil {
			log.Errorf("Connection %s: OpCustom is undefined", connName)
			return makeErrResponse(pkt, protocol.ErrBadOpcode)
		}

		res, err := customOpFunc(ctx, pkt.Operation)
		if err != nil {
			log.Errorf("Connection %s: OpCustom returned error: %v", connName, err)
			code := protocol.ErrInternal
			if err, ok := err.(protocol.Error); ok {
				code = err
			}
			return makeErrResponse(pkt, code)
		}
		return makeRespondResponse(pkt, res)

	case protocol.OpEd25519Sign:
		loadStart := time.Now()
		key, err := s.keys.Get(ctx, &pkt.Operation)
		logKeyLoadDuration(loadStart)
		if err != nil {
			log.Errorf("failed to load key with sni=%s ip=%s ski=%v: %v", pkt.Operation.SNI, pkt.Operation.ServerIP, pkt.Operation.SKI, err)
			return makeErrResponse(pkt, protocol.ErrInternal)
		} else if key == nil {
			log.Errorf("failed to load key with sni=%s ip=%s ski=%v: %v", pkt.Operation.SNI, pkt.Operation.ServerIP, pkt.Operation.SKI, protocol.ErrKeyNotFound)
			return makeErrResponse(pkt, protocol.ErrKeyNotFound)
		}

		if ed25519Key, ok := key.(ed25519.PrivateKey); ok {
			sig := ed25519.Sign(ed25519Key, pkt.Operation.Payload)
			return makeRespondResponse(pkt, sig)
		}

		sig, err := key.Sign(rand.Reader, pkt.Operation.Payload, crypto.Hash(0))
		if err != nil {
			log.Errorf("Connection: %s: Signing error: %v", connName, err)
			return makeErrResponse(pkt, protocol.ErrCrypto)
		}
		return makeRespondResponse(pkt, sig)

	case protocol.OpRSADecrypt:
		loadStart := time.Now()
		key, err := s.keys.Get(ctx, &pkt.Operation)
		logKeyLoadDuration(loadStart)
		if err != nil {
			log.Errorf("failed to load key with sni=%s ip=%s ski=%v: %v", pkt.Operation.SNI, pkt.Operation.ServerIP, pkt.Operation.SKI, err)
			return makeErrResponse(pkt, protocol.ErrInternal)
		} else if key == nil {
			log.Errorf("failed to load key with sni=%s ip=%s ski=%v: %v", pkt.Operation.SNI, pkt.Operation.ServerIP, pkt.Operation.SKI, protocol.ErrKeyNotFound)
			return makeErrResponse(pkt, protocol.ErrKeyNotFound)
		}

		if _, ok := key.Public().(*rsa.PublicKey); !ok {
			log.Errorf("Connection %v: %s: Key is not RSA", connName, protocol.ErrCrypto)
			return makeErrResponse(pkt, protocol.ErrCrypto)
		}

		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			// Decrypt without removing padding; that's the client's responsibility.
			ptxt, err := textbook_rsa.Decrypt(rsaKey, pkt.Operation.Payload)
			if err != nil {
				log.Errorf("connection %v: %v", connName, err)
				return makeErrResponse(pkt, protocol.ErrCrypto)
			}
			return makeRespondResponse(pkt, ptxt)
		}

		rsaKey, ok := key.(crypto.Decrypter)
		if !ok {
			log.Errorf("Connection %v: %s: Key is not Decrypter", connName, protocol.ErrCrypto)
			return makeErrResponse(pkt, protocol.ErrCrypto)
		}

		ptxt, err := rsaKey.Decrypt(nil, pkt.Operation.Payload, nil)
		if err != nil {
			log.Errorf("Connection %v: %s: Decryption error: %v", connName, protocol.ErrCrypto, err)
			return makeErrResponse(pkt, protocol.ErrCrypto)
		}

		return makeRespondResponse(pkt, ptxt)

	case protocol.OpRSASignMD5SHA1, protocol.OpECDSASignMD5SHA1:
		opts = crypto.MD5SHA1
	case protocol.OpRSASignSHA1, protocol.OpECDSASignSHA1:
		opts = crypto.SHA1
	case protocol.OpRSASignSHA224, protocol.OpECDSASignSHA224:
		opts = crypto.SHA224
	case protocol.OpRSASignSHA256, protocol.OpRSAPSSSignSHA256, protocol.OpECDSASignSHA256:
		opts = crypto.SHA256
	case protocol.OpRSASignSHA384, protocol.OpRSAPSSSignSHA384, protocol.OpECDSASignSHA384:
		opts = crypto.SHA384
	case protocol.OpRSASignSHA512, protocol.OpRSAPSSSignSHA512, protocol.OpECDSASignSHA512:
		opts = crypto.SHA512
	case protocol.OpPong, protocol.OpResponse, protocol.OpError:
		log.Errorf("Connection  %v: %s: %s is not a valid request Opcode\n", connName, protocol.ErrUnexpectedOpcode, pkt.Operation.Opcode)
		return makeErrResponse(pkt, protocol.ErrUnexpectedOpcode)
	default:
		return makeErrResponse(pkt, protocol.ErrBadOpcode)
	}

	switch pkt.Operation.Opcode {
	case protocol.OpRSAPSSSignSHA256, protocol.OpRSAPSSSignSHA384, protocol.OpRSAPSSSignSHA512:
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: opts.HashFunc()}
	}
	loadStart := time.Now()
	key, err := s.keys.Get(ctx, &pkt.Operation)
	logKeyLoadDuration(loadStart)
	if err != nil {
		log.Errorf("failed to load key with sni=%s ip=%s ski=%v: %v", pkt.Operation.SNI, pkt.Operation.ServerIP, pkt.Operation.SKI, err)
		return makeErrResponse(pkt, protocol.ErrInternal)
	} else if key == nil {
		log.Errorf("failed to load key with sni=%s ip=%s ski=%v: %v", pkt.Operation.SNI, pkt.Operation.ServerIP, pkt.Operation.SKI, protocol.ErrKeyNotFound)
		return makeErrResponse(pkt, protocol.ErrKeyNotFound)
	}

	signSpan, _ := opentracing.StartSpanFromContext(ctx, "execute.Sign")
	defer signSpan.Finish()
	var sig []byte
	sig, err = key.Sign(rand.Reader, pkt.Operation.Payload, opts)
	if err != nil {
		tracing.LogError(span, err)
		log.Errorf("Connection %v: %s: Signing error: %v\n", connName, protocol.ErrCrypto, err)
		return makeErrResponse(pkt, protocol.ErrCrypto)
	}

	return makeRespondResponse(pkt, sig)
}

func (s *Server) limitedDo(ctx context.Context, pkt *protocol.Packet, connName string) response {

	span, ctx := opentracing.StartSpanFromContext(ctx, "server.limitedDo")
	defer span.Finish()
	log.Debugf("connection %s: limited=true opcode=%s id=%d sni=%s ip=%s ski=%v",
		connName,
		pkt.Operation.Opcode,
		pkt.Header.ID,
		pkt.Operation.SNI,
		pkt.Operation.ServerIP,
		pkt.Operation.SKI)
	switch pkt.Operation.Opcode {
	case protocol.OpPing:
		return makePongResponse(pkt, pkt.Operation.Payload)
	case protocol.OpRPC:
		codec := newServerCodec(pkt.Payload)

		err := s.limitedDispatcher.ServeRequest(codec)
		if err != nil {
			log.Errorf("Connection %s: ServeRPC: %v", connName, err)
			return makeErrResponse(pkt, protocol.ErrInternal)
		}
		return makeRespondResponse(pkt, codec.response)
	default:
		return makeErrResponse(pkt, protocol.ErrBadOpcode)
	}
}

func (s *Server) addListener(l net.Listener) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.shutdown {
		return fmt.Errorf("attempt to add listener after calling Close")
	}
	if _, ok := s.listeners[l]; ok {
		return fmt.Errorf("attempt to add duplicate listener: %s", l.Addr().String())
	}
	s.listeners[l] = make(map[net.Conn]struct{})
	return nil
}

// Serve accepts incoming connections on the Listener l, creating a new
// pair of service goroutines for each. The first time l.Accept returns a
// non-temporary error, everything will be torn down.
//
// If l is neither a TCP listener nor a Unix listener, then the timeout will be
// taken to be the lower of the TCP timeout and the Unix timeout specified in
// the server's config.
func (s *Server) Serve(l net.Listener) error {
	if err := s.addListener(l); err != nil {
		return fmt.Errorf("Serve: %w", err)
	}

	for {
		c, err := accept(l)
		if err != nil {
			log.Errorf("Accept error: %v; shutting down server", err)
			return fmt.Errorf("Accept error: %w", err)
		}
		go s.spawn(l, c)
	}
}

func (s *Server) spawn(l net.Listener, c net.Conn) {
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

	// Perform the TLS handshake explicitly so we can determine if this is a
	// limited connection.
	tconn := tls.Server(c, s.tlsConfig)
	err := tconn.Handshake()
	if err != nil {
		// We get EOF here if the client closes the connection immediately after
		// it's accepted, which is typical of a TCP health check.
		if err == io.EOF {
			log.Debugf("connection %v: closed by client before TLS handshake", c.RemoteAddr())
		} else {
			log.Errorf("connection %v: TLS handshake failed: %v", c.RemoteAddr(), err)
		}
		tconn.Close()
		return
	}
	connState := tconn.ConnectionState()
	certmetrics.Observe(certmetrics.CertSourceFromCerts(fmt.Sprintf("listener: %s", l.Addr().String()), connState.PeerCertificates)...)
	limited, err := s.config.isLimited(connState)
	if err != nil {
		log.Errorf("connection %v: could not determine if limited: %v", c.RemoteAddr(), err)
		logConnFailure()
		tconn.Close()
		return
	}

	var connStr string
	if limited {
		connStr = fmt.Sprintf("limited connection %v", c.RemoteAddr())
	} else {
		connStr = fmt.Sprintf("connection %v", c.RemoteAddr())
	}

	// Acquire the lock to atomically spawn the reader/writer goroutines for
	// this connection and add it to the connections map.
	s.mtx.Lock()
	if s.shutdown {
		s.mtx.Unlock()
		log.Debugf("%s: rejected (server is shutting down)", connStr)
		tconn.Close()
		return
	}

	s.listeners[l][tconn] = struct{}{}
	s.mtx.Unlock()
	log.Debugf("%s: serving", connStr)
	handler := &handler{
		name:     connStr,
		s:        s,
		tokens:   semaphore.NewWeighted(int64(s.config.maxConnPendingRequests)),
		limited:  limited,
		conn:     tconn,
		listener: l,
		timeout:  timeout,
	}
	err = handler.loop()

	log.Debugf("%s: closed with err %v", connStr, err)

	// Acquire the lock again to remove the handle from the connections map. If
	// we've shutdown in the meantime this is a safe no-op.
	s.mtx.Lock()
	delete(s.listeners[l], tconn)
	s.mtx.Unlock()
	log.Debugf("%s: removed", connStr)
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
			return fmt.Errorf("UnixListenAndServe: %w", err)
		}

		log.Infof("Listening at unix://%s\n", l.Addr())
		return s.Serve(l)
	}
	return errors.New("can't listen on empty path")
}

// Close shuts down the listeners and their active connections.
func (s *Server) Close() error {
	// Close each active listener. This will result in the blocking calls to
	// Accept to immediately return with error, which will trigger the teardown
	// of all active connections and associated goroutines.
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.shutdown {
		return fmt.Errorf("Close called multiple times")
	}

	s.shutdown = true
	for l, conns := range s.listeners {
		delete(s.listeners, l)

		log.Debugf("Shutting down %v; closing %d active connections", l.Addr().String(), len(conns))
		l.Close()
		for conn := range conns {
			conn.Close()
		}
	}

	return nil
}

// ServeConfig is used to configure a call to Server.Serve. It specifies the
// number of ECDSA worker goroutines, other worker goroutines, and background
// worker goroutines to use. It also specifies the network connection timeout.
type ServeConfig struct {
	maxConnPendingRequests  int
	tcpTimeout, unixTimeout time.Duration
	isLimited               func(state tls.ConnectionState) (bool, error)
	customOpFunc            CustomOpFunction
}

const (
	defaultTCPTimeout  = time.Second * 30
	defaultUnixTimeout = time.Hour
)

// DefaultServeConfig constructs a default ServeConfig with the following
// values:
//   - The number of ECDSA workers is max(2, runtime.NumCPU())
//   - The number of RSA workers is max(2, runtime.NumCPU())
//   - The number of other workers is 2
//   - The TCP connection timeout is 30 seconds
//   - The Unix connection timeout is 1 hour
//   - All connections have full power
func DefaultServeConfig() *ServeConfig {
	return &ServeConfig{
		tcpTimeout:             defaultTCPTimeout,
		unixTimeout:            defaultUnixTimeout,
		maxConnPendingRequests: 1024,
		isLimited:              func(state tls.ConnectionState) (bool, error) { return false, nil },
	}
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

// WithIsLimited specifies the function f to call to determine if a connection is limited.
// f is called on each new connection, and if f returns true the connection will only serve
// OpPing and OpRPC requests, and only RPCs registered with RegisterLimitedRPC
func (s *ServeConfig) WithIsLimited(f func(state tls.ConnectionState) (bool, error)) *ServeConfig {
	s.isLimited = f
	return s
}

// CustomOpFunction is the signature for custom opcode functions.
//
// If it returns a non-nil error which implements protocol.Error, the server
// will return it directly. Otherwise it will return protocol.ErrInternal.
type CustomOpFunction func(context.Context, protocol.Operation) ([]byte, error)

// WithCustomOpFunction defines a function to use with the OpCustom opcode.
func (s *ServeConfig) WithCustomOpFunction(f CustomOpFunction) *ServeConfig {
	s.customOpFunc = f
	return s
}

// CustomOpFunc returns the CustomOpFunc
func (s *ServeConfig) CustomOpFunc() CustomOpFunction {
	return s.customOpFunc
}

// WithMaxConnPendingRequests allows customization of the limit on pending requests
func (s *ServeConfig) WithMaxConnPendingRequests(n int) *ServeConfig {
	s.maxConnPendingRequests = n
	return s
}

// MaxConnPendingRequests returns the number of allowed pending requests
func (s *ServeConfig) MaxConnPendingRequests() int {
	return s.maxConnPendingRequests
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
		return fmt.Errorf("WriteResponse: %w", err)
	} else if err := enc.Encode(body); err != nil {
		return fmt.Errorf("WriteResponse: %w", err)
	}

	sc.response = buff.Bytes()
	return nil
}

func (sc *serverCodec) Close() error {
	return errors.New("an rpc server codec cannot be closed")
}
