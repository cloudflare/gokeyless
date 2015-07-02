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
	"log"
	"net"
	"sync"
	"time"

	"github.com/cloudflare/gokeyless"
)

// Server is a Keyless Server capable of performing opaque key operations.
type Server struct {
	// TCP address to listen on
	Addr string
	// Config is initialized with the auth configuration used for communicating with keyless clients.
	Config *tls.Config
	// Log used to output informational data.
	Log *log.Logger
	// Mutex for non thread-safe map operations.
	sync.Mutex
	// keys maps all known key SKIs to their corresponding keys.
	keys map[gokeyless.SKI]crypto.Signer
	// digests maps keys' digests to their SKI.
	digests map[gokeyless.Digest]gokeyless.SKI
}

// NewServer prepares a TLS server capable of receiving connections from keyless clients
func NewServer(cert tls.Certificate, keylessCA *x509.CertPool, addr string, logOut io.Writer) *Server {
	return &Server{
		Addr: addr,
		Config: &tls.Config{
			RootCAs:      keylessCA,
			Certificates: []tls.Certificate{cert},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
		},
		Log:     log.New(logOut, "[server] ", log.LstdFlags),
		keys:    make(map[gokeyless.SKI]crypto.Signer),
		digests: make(map[gokeyless.Digest]gokeyless.SKI),
	}
}

// NewServerFromFile reads certificate, key, and CA files in order to create a Server.
func NewServerFromFile(certFile, keyFile, caFile, addr string, logOut io.Writer) (*Server, error) {
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
		return nil, errors.New("gokeyless/client: failed to read keyless CA from PEM")
	}
	return NewServer(cert, keylessCA, addr, logOut), nil
}

// RegisterKey adds a new key to the server's internal repertoire.
func (s *Server) RegisterKey(key crypto.Signer) error {
	ski, err := gokeyless.GetSKI(key.Public())
	if err != nil {
		return err
	}

	s.Lock()
	defer s.Unlock()

	if digest, ok := gokeyless.GetDigest(key.Public()); ok {
		s.digests[digest] = ski
	}
	s.keys[ski] = key

	s.Log.Printf("Registering key with SKI: %X", ski)
	return nil
}

func (s *Server) getKey(ski gokeyless.SKI, digest gokeyless.Digest) (key crypto.Signer, ok bool) {
	s.Lock()
	defer s.Unlock()
	if key, ok = s.keys[ski]; !ok {
		s.Log.Println("Couldn't look up key based on SKI, trying Digest.")
		if ski, ok = s.digests[digest]; ok {
			key, ok = s.keys[ski]
			return
		}
	}
	return
}

func (s *Server) handle(conn *gokeyless.Conn) {
	defer conn.Close()
	s.Log.Println("Handling new connection...")
	// Continuosly read request Headers from conn and respond
	// until a connection error (Read/Write failure) is encountered.
	var connError error
	for connError == nil {
		conn.SetDeadline(time.Now().Add(time.Hour))

		var h *gokeyless.Header
		if h, connError = conn.ReadHeader(); connError != nil {
			continue
		}

		s.Log.Printf("version:%d.%d id:%d op:%s", h.MajorVers, h.MinorVers, h.ID, h.Body.Opcode)

		var opts crypto.SignerOpts
		var isRSA bool
		var key crypto.Signer
		var ok bool
		switch h.Body.Opcode {
		case gokeyless.OpPing:
			connError = conn.RespondPong(h.ID, h.Body.Payload)
			continue

		case gokeyless.OpRSADecrypt:
			if key, ok = s.getKey(h.Body.SKI, h.Body.Digest); !ok {
				s.Log.Println(gokeyless.ErrKeyNotFound)
				connError = conn.RespondError(h.ID, gokeyless.ErrKeyNotFound)
				continue
			}

			if _, ok = key.Public().(*rsa.PublicKey); !ok {
				s.Log.Printf("%s: Key is not RSA\n", gokeyless.ErrCrypto)
				connError = conn.RespondError(h.ID, gokeyless.ErrCrypto)
				continue
			}

			rsaKey, ok := key.(crypto.Decrypter)
			if !ok {
				s.Log.Printf("%s: Key is not Decrypter\n", gokeyless.ErrCrypto)
				connError = conn.RespondError(h.ID, gokeyless.ErrCrypto)
				continue
			}

			ptxt, err := rsaKey.Decrypt(nil, h.Body.Payload, nil)
			if err != nil {
				s.Log.Printf("%s: Decryption error: %v", gokeyless.ErrCrypto, err)
				connError = conn.RespondError(h.ID, gokeyless.ErrCrypto)
				continue
			}

			connError = conn.Respond(h.ID, ptxt)
			continue
		case gokeyless.OpRSASignMD5SHA1:
			isRSA = true
			fallthrough
		case gokeyless.OpECDSASignMD5SHA1:
			opts = crypto.MD5SHA1
		case gokeyless.OpRSASignSHA1:
			isRSA = true
			fallthrough
		case gokeyless.OpECDSASignSHA1:
			opts = crypto.SHA1
		case gokeyless.OpRSASignSHA224:
		case gokeyless.OpECDSASignSHA224:
			opts = crypto.SHA224
		case gokeyless.OpRSASignSHA256:
			isRSA = true
			fallthrough
		case gokeyless.OpECDSASignSHA256:
			opts = crypto.SHA256
		case gokeyless.OpRSASignSHA384:
			isRSA = true
			fallthrough
		case gokeyless.OpECDSASignSHA384:
			opts = crypto.SHA384
		case gokeyless.OpRSASignSHA512:
			isRSA = true
			fallthrough
		case gokeyless.OpECDSASignSHA512:
			opts = crypto.SHA512
		case gokeyless.OpPong:
			fallthrough
		case gokeyless.OpResponse:
			fallthrough
		case gokeyless.OpError:
			s.Log.Printf("%s: %s is not a valid request Opcode\n", gokeyless.ErrUnexpectedOpcode, h.Body.Opcode)
			connError = conn.RespondError(h.ID, gokeyless.ErrUnexpectedOpcode)
			continue
		default:
			connError = conn.RespondError(h.ID, gokeyless.ErrBadOpcode)
			continue
		}

		if key, ok = s.getKey(h.Body.SKI, h.Body.Digest); !ok {
			s.Log.Println(gokeyless.ErrKeyNotFound)
			connError = conn.RespondError(h.ID, gokeyless.ErrKeyNotFound)
			continue
		}

		// Ensure we don't perform an ECDSA sign for an RSA request.
		if _, ok := key.Public().(*rsa.PublicKey); isRSA && !ok {
			s.Log.Printf("%s: request is RSA, but key is ECDSA\n", gokeyless.ErrCrypto)
			connError = conn.RespondError(h.ID, gokeyless.ErrCrypto)
			continue
		}

		sig, err := key.Sign(rand.Reader, h.Body.Payload, opts)
		if err != nil {
			s.Log.Printf("%s: Signing error: %v\n", gokeyless.ErrCrypto, err)
			connError = conn.RespondError(h.ID, gokeyless.ErrCrypto)
			continue
		}

		connError = conn.Respond(h.ID, sig)
	}
	s.Log.Printf("Connection error: %v\n", connError)
	return
}

// Serve accepts incoming connections on the Listener l, creating a new service goroutine for each.
func (s *Server) Serve(l net.Listener) error {
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}

		go s.handle(gokeyless.NewConn(tls.Server(c, s.Config)))
	}

}

// ListenAndServe listens on the TCP network address s.Addr and then
// calls Serve to handle requests on incoming keyless connections.
func (s *Server) ListenAndServe() error {
	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}

	s.Log.Printf("Listenting at %s\n", l.Addr())

	return s.Serve(l)
}
