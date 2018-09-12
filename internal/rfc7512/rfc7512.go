// +build cgo

// Package rfc7512 provides a parser for the PKCS #11 URI format as specified in
// RFC 7512: The PKCS #11 URI Scheme. Additionally, it provides a wrapper around
// the crypto11 package for loading a key pair as a crypto.Signer object.
package rfc7512

import (
	"crypto"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ThalesIgnite/crypto11"
	"github.com/cloudflare/cfssl/log"
	"github.com/miekg/pkcs11"
)

// PKCS11URI contains the information for accessing a PKCS #11 storage object,
// such as a public key, private key, or a certificate.
type PKCS11URI struct {
	// path attributes:
	Token  string //        token <- CK_TOKEN_INFO
	Manuf  string // manufacturer <- CK_TOKEN_INFO
	Serial string //       serial <- CK_TOKEN_INTO
	Model  string //        model <- CK_TOKEN_INFO

	LibManuf string // library-manufacturer <- CK_INFO
	LibDesc  string //  library-description <- CK_INFO
	LibVer   string //      library-version <- CK_INFO

	Object []byte // object <- CKA_LABEL
	Type   string //   type <- CKA_CLASS
	ID     []byte //     id <- CKA_ID

	SlotManuf string // slot-manufacturer <- CK_SLOT_INFO
	SlotDesc  string //  slot-description <- CK_SLOT_INFO
	SlotID    uint   //           slot-id <- CK_SLOT_ID

	// query attributes:
	PinSource string // pin-source
	PinValue  string //  pin-value

	ModuleName string // module-name
	ModulePath string // module-path

	// Vendor specific query attributes:
	MaxSessions int           // max-sessions
	IdleTimeout time.Duration // idle-timeout

	raw string
}

// ParsePKCS11URI decodes a PKCS #11 URI and returns it as a PKCS11URI object.
//
// A PKCS #11 URI is a sequence of attribute value pairs separated by a
// semicolon that form a one-level path component, optionally followed
// by a query. The general form represented is:
//
//	pkcs11:path-component[?query-component]
//
// The URI path component contains attributes that identify a resource
// in a one-level hierarchy provided by Cryptoki producers.  The query
// component can contain a few attributes that may be needed to retrieve
// the resource identified by the URI path component.  Attributes in the
// path component are delimited by the ';' character, attributes in the
// query component use '&' as a delimiter.
//
// For more information read: https://tools.ietf.org/html/rfc7512#section-2.3
//
// An error is returned if the input string does not appear to follow the rules
// or if there are unrecognized path or query attributes.
func ParsePKCS11URI(uri string) (*PKCS11URI, error) {
	// Check that the URI matches the specification from RFC 7512:
	aChar := "[a-z-_]"
	pChar := "[a-zA-Z0-9-_.~%:\\[\\]@!\\$'\\(\\)\\*\\+,=&]"
	pAttr := aChar + "+=" + pChar + "+"
	pClause := "(" + pAttr + ";)*(" + pAttr + ")"
	qChar := "[a-zA-Z0-9-_.~%:\\[\\]@!\\$'\\(\\)\\*\\+,=/\\?\\|]"
	qAttr := aChar + "+=" + qChar + "+"
	qClause := "(" + qAttr + "&)*(" + qAttr + ")"
	r, err := regexp.Compile("^pkcs11:" + pClause + "(\\?" + qClause + ")?$")
	if err != nil {
		return nil, err
	}

	if !r.MatchString(uri) {
		return nil, fmt.Errorf("uri %q is malformed", uri)
	}

	pk11uri := PKCS11URI{
		raw: uri,
	}

	var pAttrs []string
	var qAttrs []string
	var parts []string
	var value string

	// Separate the scheme name, path, and query attributes:
	uri = strings.Split(uri, "pkcs11:")[1]
	parts = strings.Split(uri, "?")
	pAttrs = strings.Split(parts[0], ";")
	if 1 < len(parts) {
		qAttrs = strings.Split(parts[1], "&")
	}

	// Parse the path attributes:
	for _, attr := range pAttrs {
		parts = strings.Split(attr, "=")
		parts[0] = strings.Trim(parts[0], " \n\t\r")
		if len(parts) == 2 {
			parts[1] = strings.Trim(parts[1], " \n\t\r")
			value, err = url.QueryUnescape(parts[1])
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("uri %q contains an unrecognized query attribute: %s", pk11uri.raw, parts[0])
		}
		switch parts[0] {
		case "token":
			pk11uri.Token = value
		case "manufacturer":
			pk11uri.Manuf = value
		case "serial":
			pk11uri.Serial = value
		case "model":
			pk11uri.Model = value
		case "library-manufacturer":
			pk11uri.LibManuf = value
		case "library-description":
			pk11uri.LibDesc = value
		case "library-version":
			// TODO 1*DIGIT [ "." 1*DIGIT ]
			pk11uri.LibVer = value
		case "object":
			pk11uri.Object = []byte(value)
		case "type":
			// TODO public, private, cert, secret-key, data
			pk11uri.Type = value
		case "id":
			pk11uri.ID = []byte(value)
		case "slot-manufacturer":
			pk11uri.SlotManuf = value
		case "slot-description":
			pk11uri.SlotDesc = value
		case "slot-id":
			// TODO the bit size is not clarified.
			id, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return nil, err
			}
			pk11uri.SlotID = uint(id)
		default:
			return nil, fmt.Errorf("uri %q contains an unrecognized query attribute: %s", pk11uri.raw, parts[0])
		}
	}

	// Parse the query attributes:
	for _, attr := range qAttrs {
		parts = strings.Split(attr, "=")
		parts[0] = strings.Trim(parts[0], " \n\t\r")
		if len(parts) == 2 {
			parts[1] = strings.Trim(parts[1], " \n\t\r")
			value, err = url.QueryUnescape(parts[1])
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("uri %q contains an unrecognized query attribute: %s", pk11uri.raw, parts[0])
		}
		switch parts[0] {
		case "pin-source":
			pk11uri.PinSource = value
		case "pin-value":
			pk11uri.PinValue = value
		case "module-name":
			pk11uri.ModuleName = value
		case "module-path":
			pk11uri.ModulePath = value
		case "max-sessions":
			maxSessions, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return nil, err
			}
			pk11uri.MaxSessions = int(maxSessions)
		case "idle-timeout":
			d, err := time.ParseDuration(value)
			if err != nil {
				return nil, err
			}
			pk11uri.IdleTimeout = d
		default:
			return nil, fmt.Errorf("uri %q contains an unrecognized query attribute: %s", pk11uri.raw, parts[0])
		}
	}

	return &pk11uri, nil
}

func (pk11uri *PKCS11URI) String() string {
	return pk11uri.raw
}

// LoadPKCS11Signer attempts to load a Signer given a PKCS11URI object that
// identifies a key pair. At least three attributes must be specified:
//
//	Module:	use ModulePath to locate the PKCS #11 module library.
//	Token:	use Serial or Token to specify the PKCS #11 token.
//	Slot:	use SlotID, ID, or Object to specify the PKCS #11 key pair.
//
// For certain modules, a query attribute max-sessions is required in order to
// prevent openning too many sessions to the module. Certain additional attributes,
// such as pin-value, may be necessary depending on the situation. Refer to the
// documentation for your PKCS #11 module for more details.
//
// An error is returned if the crypto11 module cannot find the module, token,
// or the specified object.
func LoadPKCS11Signer(pk11uri *PKCS11URI) (crypto.Signer, error) {
	config := &crypto11.PKCS11Config{
		Path:            pk11uri.ModulePath,
		TokenSerial:     pk11uri.Serial,
		TokenLabel:      pk11uri.Token,
		Pin:             pk11uri.PinValue,
		MaxSessions:     pk11uri.MaxSessions,
		IdleTimeout:     pk11uri.IdleTimeout,
		PoolWaitTimeout: 10 * time.Second,
	}

	_, err := crypto11.Configure(config)
	if err != nil {
		return nil, err
	}

	signer, err := initSigner(pk11uri)
	if err != nil {
		return nil, err
	}

	return &privateKey{
		uri:          pk11uri,
		signer:       signer,
		lastInitTime: time.Now(),
	}, nil
}

func initSigner(pk11uri *PKCS11URI) (crypto.Signer, error) {
	key, err := crypto11.FindKeyPairOnSlot(pk11uri.SlotID, pk11uri.ID, pk11uri.Object)
	if err != nil {
		return nil, err
	}

	switch v := key.(type) {
	case *crypto11.PKCS11PrivateKeyECDSA:
		if err := testSign(v); err != nil {
			return nil, err
		}
		return v, nil
	case *crypto11.PKCS11PrivateKeyRSA:
		if err := testSign(v); err != nil {
			return nil, err
		}
		return v, nil
	default:
		return nil, fmt.Errorf("uri %q uses an unsupported key type", pk11uri.String())
	}
}

func testSign(signer crypto.Signer) error {
	_, err := signer.Sign(nil, make([]byte, 32), crypto.SHA256)
	return err
}

type privateKey struct {
	uri          *PKCS11URI
	signer       crypto.Signer
	lastInitTime time.Time // last time the signer was initialized
	lock         sync.RWMutex
}

func (pk *privateKey) Public() crypto.PublicKey {
	pk.lock.RLock()
	defer pk.lock.RUnlock()
	return pk.signer.Public()
}

func (pk *privateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	pk.lock.RLock()
	lastInitTime := pk.lastInitTime
	sig, err := pk.signer.Sign(rand, digest, opts)
	pk.lock.RUnlock()

	if err == nil {
		return sig, nil
	}

	// Idle sessions are closed out by the connection pool, and if that happens
	// our object handles will be invalidated. We attempt to gracefully recover
	// by re-initializing the signer from a single goroutine.
	perr, ok := err.(pkcs11.Error)
	if !ok || perr != pkcs11.CKR_OBJECT_HANDLE_INVALID {
		return nil, err
	} else if time.Since(lastInitTime) < 100*time.Millisecond { // arbitrary threshold
		return nil, err
	}

	log.Debugf("re-initializing uri %q after encountering %v", pk.uri, err)

	pk.lock.Lock()
	if pk.lastInitTime == lastInitTime { // check again now that we have the lock
		signer, err := initSigner(pk.uri)
		if err != nil {
			pk.lock.Unlock()
			return nil, err
		}
		pk.signer = signer
		pk.lastInitTime = time.Now()
	}
	pk.lock.Unlock()

	return pk.signer.Sign(rand, digest, opts)
}
