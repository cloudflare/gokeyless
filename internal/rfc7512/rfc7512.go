package rfc7512

import (
	"crypto"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/cbroglie/crypto11"
)

// A PKCS11URI represents a PKCS#11 object stored on a PKCS#11 token and
// information for accessing it. The general form represented is:
//
//	pkcs11:path-attr[?query-attr]
//
// Path and query attributes are delimited by ';' and '&', respectively.
// For more information read: https://tools.ietf.org/html/rfc7512#section-2.3
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
	MaxSessions int // max-sessions
}

// ParsePKCS11URI decodes a PKCS#11 URI as defined in RFC 7512 into an PKCS11URI object.
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
	r, _ := regexp.Compile("^pkcs11:" + pClause + "(\\?" + qClause + ")?$")

	if !r.MatchString(uri) {
		return nil, fmt.Errorf("PKCS#11 URI is malformed: %s", uri)
	}

	var pk11uri PKCS11URI
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
			value, _ = url.QueryUnescape(parts[1])
		} else {
			return nil, fmt.Errorf("Unrecognized PKCS#11 URI Path Attribute: %s", parts[0])
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
			id, _ := strconv.ParseUint(value, 10, 32)
			pk11uri.SlotID = uint(id)
		default:
			return nil, fmt.Errorf("Unrecognized PKCS#11 URI Path Attribute: %s", parts[0])
		}
	}

	// Parse the query attributes:
	for _, attr := range qAttrs {
		parts = strings.Split(attr, "=")
		parts[0] = strings.Trim(parts[0], " \n\t\r")
		if len(parts) == 2 {
			parts[1] = strings.Trim(parts[1], " \n\t\r")
			value, _ = url.QueryUnescape(parts[1])
		} else {
			return nil, fmt.Errorf("Unrecognized PKCS#11 URI Query Attribute: %s", parts[0])
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
			maxSessions, _ := strconv.ParseUint(value, 10, 32)
			pk11uri.MaxSessions = int(maxSessions)
		default:
			return nil, fmt.Errorf("Unrecognized PKCS#11 URI Query Attribute: %s", parts[0])
		}
	}

	return &pk11uri, nil
}

// LoadPKCS11Key attempts to load a Signer given a PKCS11URI object identifier.
// An error is returned if the crypto11 module cannot find the module, token,
// or the specified object.
func LoadPKCS11Key(pk11uri *PKCS11URI) (crypto.Signer, error) {
	config := &crypto11.PKCS11Config{
		Path:        pk11uri.ModulePath,
		TokenSerial: pk11uri.Serial,
		TokenLabel:  pk11uri.Token,
		Pin:         pk11uri.PinValue,
		MaxSessions: pk11uri.MaxSessions,
	}

	_, err := crypto11.Configure(config)
	if err != nil {
		return nil, err
	}

	key, err := crypto11.FindKeyPairOnSlot(pk11uri.SlotID, pk11uri.ID, pk11uri.Object)
	if err != nil {
		return nil, err
	}

	return key.(crypto.Signer), nil
}
