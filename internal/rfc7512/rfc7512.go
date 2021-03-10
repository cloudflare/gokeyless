// +build pkcs11,cgo

// Package rfc7512 provides a parser for the PKCS #11 URI format as specified in
// RFC 7512: The PKCS #11 URI Scheme. Additionally, it provides a wrapper around
// the crypto11 package for loading a key pair as a crypto.Signer object.
package rfc7512

import (
	"crypto"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ThalesIgnite/crypto11"
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
	SlotID    *int   //           slot-id <- CK_SLOT_ID

	// query attributes:
	PinSource string // pin-source
	PinValue  string //  pin-value

	ModuleName string // module-name
	ModulePath string // module-path

	// Vendor specific query attributes:
	MaxSessions int // max-sessions
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
	if IsPKCS11URI(uri) {
		return nil, fmt.Errorf("error parsing pkcs11 uri %q: invalid format", uri)
	}

	var pk11uri PKCS11URI
	var pAttrs, qAttrs []string

	// Separate the scheme name, path, and query attributes:
	uri = strings.Split(uri, "pkcs11:")[1]
	parts := strings.Split(uri, "?")
	pAttrs = strings.Split(parts[0], ";")
	if len(parts) > 1 {
		qAttrs = strings.Split(parts[1], "&")
	}

	// Parse the path attributes:
	for _, attr := range pAttrs {
		parts := strings.Split(attr, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("error parsing pkcs11 attribute %q: invalid format", parts[0])
		}
		parts[0] = strings.Trim(parts[0], " \n\t\r")
		parts[1] = strings.Trim(parts[1], " \n\t\r")

		value, err := url.QueryUnescape(parts[1])
		if err != nil {
			return nil, fmt.Errorf("error parsing pkcs11 attribute %q: %v", parts[0], err)
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
			id, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("error parsing pkcs11 attribute %q: %v", parts[0], err)
			}
			pk11uri.SlotID = &id
		default:
			return nil, fmt.Errorf("error parsing pkcs11 attribute %q: unknown attribute", parts[0])
		}
	}

	// Parse the query attributes:
	for _, attr := range qAttrs {
		parts := strings.Split(attr, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("error parsing pkcs11 attribute %q: invalid format", parts[0])
		}
		parts[0] = strings.Trim(parts[0], " \n\t\r")
		parts[1] = strings.Trim(parts[1], " \n\t\r")

		value, err := url.QueryUnescape(parts[1])
		if err != nil {
			return nil, fmt.Errorf("error parsing pkcs11 attribute %q: %v", parts[0], err)
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
			maxSessions, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("error parsing pkcs11 attribute %q: %v", parts[0], err)
			}
			pk11uri.MaxSessions = maxSessions
		default:
			return nil, fmt.Errorf("error parsing pkcs11 attribute %q: unknown attribute", parts[0])
		}
	}

	return &pk11uri, nil
}

// LoadPKCS11Signer attempts to load a Signer given a PKCS11URI object that
// identifies a key pair. At least three attributes must be specified:
//
//	Module:	use ModulePath to locate the PKCS #11 module library.
//	Token:	use Serial or Token to specify the PKCS #11 token.
//	Slot:	use SlotID, ID, or Object to specify the PKCS #11 key pair.
//
// For certain modules, a query attribute max-sessions is required in order to
// prevent opening too many sessions to the module. Certain additional attributes,
// such as pin-value, may be necessary depending on the situation. Refer to the
// documentation for your PKCS #11 module for more details.
//
// An error is returned if the crypto11 module cannot find the module, token,
// or the specified object.
func LoadPKCS11Signer(pk11uri *PKCS11URI) (crypto.Signer, error) {
	config := &crypto11.Config{
		Path:            pk11uri.ModulePath,
		TokenSerial:     pk11uri.Serial,
		TokenLabel:      pk11uri.Token,
		SlotNumber:      pk11uri.SlotID,
		Pin:             pk11uri.PinValue,
		MaxSessions:     pk11uri.MaxSessions,
		PoolWaitTimeout: 10 * time.Second,
	}
	// crypto11 uses 1 of the sessions in the background for itself, so the
	// practical minimum is 2.
	if config.MaxSessions < 2 {
		config.MaxSessions = 2
	}

	context, err := crypto11.Configure(config)
	if err != nil {
		return nil, err
	}

	signer, err := context.FindKeyPair(pk11uri.ID, pk11uri.Object)
	if err != nil {
		return nil, err
	} else if signer == nil {
		return nil, fmt.Errorf("not found")
	}

	return signer, nil
}
