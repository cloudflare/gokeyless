package rfc7512

import "regexp"

var re *regexp.Regexp

func init() {
	aChar := "[a-z-_]"
	pChar := "[a-zA-Z0-9-_.~%:\\[\\]@!\\$'\\(\\)\\*\\+,=&]"
	pAttr := aChar + "+=" + pChar + "+"
	pClause := "(" + pAttr + ";)*(" + pAttr + ")"
	qChar := "[a-zA-Z0-9-_.~%:\\[\\]@!\\$'\\(\\)\\*\\+,=/\\?\\|]"
	qAttr := aChar + "+=" + qChar + "+"
	qClause := "(" + qAttr + "&)*(" + qAttr + ")"

	re = regexp.MustCompile("^pkcs11:" + pClause + "(\\?" + qClause + ")?$")
}

// IsPKCS11URI checks if the uri is in the pkcs11 format
func IsPKCS11URI(uri string) bool {
	return re.MatchString(uri)
}
