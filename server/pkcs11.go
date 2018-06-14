package server

import (
	"fmt"
	"crypto"
	"strconv"
	"strings"
	"net/url"
	"regexp"

	"github.com/thalesignite/crypto11"
	"github.com/cloudflare/cfssl/log"
)

// PKCS11URI defines a PKCS#11 URI: https://tools.ietf.org/html/rfc7512#section-2.3
type PKCS11URI struct { // pkcs11:path-attr[?query-attr]
	// path-attr: (; delimited)
	Token  string //        token <- CK_TOKEN_INFO
	Manuf  string // manufacturer <- CK_TOKEN_INFO
	Serial string //       serial <- CK_TOKEN_INTO
	Model  string //        model <- CK_TOKEN_INFO

	LibManuf string // library-manufacturer <- CK_INFO
	LibDesc  string //  library-description <- CK_INFO
	LibVer   string //      library-version <- CK_INFO

	Object []byte // object <- CKA_LABEL
	Type   string //   type <- CKA_CLASS (cert, data, private, public, or secret-key)
	Id     []byte //     id <- CKA_ID

	SlotManuf string // slot-manufacturer <- CK_SLOT_INFO
	SlotDesc  string //  slot-description <- CK_SLOT_INFO
	SlotId      uint //           slot-id <- CK_SLOT_ID

	// query-attr: (& delimited)
	PinSource string // pin-source
	PinValue  string //  pin-value

	ModuleName string // module-name
	ModulePath string // module-path
}

func RFC7512Parser(uri string) PKCS11URI {
/* FIXME: specific sections allow specific extra characters, include those as well.
   pk11-res-avail       = ":" / "[" / "]" / "@" / "!" / "$" /
                          "'" / "(" / ")" / "*" / "+" / "," / "="
   pk11-path-res-avail  = pk11-res-avail / "&"
   ; "/" and "?" in the query component MAY be unencoded but "&" MUST
   ; be encoded since it functions as a delimiter within the component.
   pk11-query-res-avail = pk11-res-avail / "/" / "?" / "|"
*/
	r, _ := regexp.Compile("pkcs11:([a-z]+=[a-zA-Z0-9%]+;)*([a-z]+=[a-zA-Z0-9%]+)(\\?([a-z]+=[a-zA-Z0-9%]+&)*([a-z]+=[a-zA-Z0-9%]+))?")

	if ! r.MatchString(uri) {
		log.Error("PKCS#11 URI is malformed.")
		return PKCS11URI{Id: []byte{}}
	}

	var pk11uri PKCS11URI

	uri = strings.Split(uri, "pkcs11:")[1]
	parts := strings.Split(uri, "?")
	pAttr := strings.Split(parts[0], ";")
	qAttr := strings.Split(parts[1], "&")

	for _, attr := range pAttr {
		// TODO: do we need to trim attr here?
		parts := strings.Split(attr, "=")
		value, _ := url.QueryUnescape(parts[1])
		switch parts[0] {
		case "token":
			pk11uri.Token = value
		case "id":
			pk11uri.Id = []byte(value)
		case "slot-id":
			id, _ := strconv.ParseUint(value, 10, 32) // FIXME what is the bit size
			pk11uri.SlotId = uint(id)
		default:
			fmt.Print(parts[0])
		}
	}

	for _, attr := range qAttr {
		// TODO: do we need to trim attr here?
		parts := strings.Split(attr, "=")
		switch parts[0] {
		case "pin-value":
			pk11uri.PinValue = parts[1]
		case "module-path":
			value, _ := url.QueryUnescape(parts[1])
			pk11uri.ModulePath = value
		default:
			fmt.Print(parts[0])
		}
	}

	return pk11uri
}

// LoadPKCS11Key attempts to load a signer from a PKCS#11 URI.
// See https://tools.ietf.org/html/rfc7512#section-2.3
func LoadPKCS11Key(pk11uri PKCS11URI) (priv crypto.Signer, err error) {
	config := &crypto11.PKCS11Config {
		Path:        pk11uri.ModulePath,
		TokenSerial: pk11uri.Serial,
		TokenLabel:  pk11uri.Token,
		Pin:         pk11uri.PinValue,
	}

	_, err = crypto11.Configure(config)
	if err != nil {
		log.Warning(err)
		return nil, err
	}

	key, err := crypto11.FindKeyPairOnSlot(pk11uri.SlotId, pk11uri.Id, pk11uri.Object)
	if err != nil {
		log.Warning(err)
		return nil, err
	}

	return key.(crypto.Signer), nil
}
