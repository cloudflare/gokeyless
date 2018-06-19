package server

import (
	"testing"
	"strings"
)

var samples string = `pkcs11:id=0
pkcs11:id=0;token=b
pkcs11:id=b?pin-value=1234
pkcs11:id=b?pin-value=1234&module-path=/a/b.so
pkcs11:id=b;token=b?pin-value=1234&module-path=/a/b.so
pkcs11:token=Thalesn6000;id=%00?module-path=/opt/nfast/toolkits/pkcs11/libcknfast.so&pin-value=1234
pkcs11:token=SoftHSM2;id=%00;slot-id=1359138056?module-path=/usr/lib64/libsofthsm2.so&pin-value=1234
pkcs11:token=YubiKey%20PIV;id=%00;slot-id=0?module-path=/usr/lib64/libykcs11.so&pin-value=123456
pkcs11:token=Gemalto;id=%04;slot-id=0?module-path=/usr/lib/libCryptoki2_64.so&pin-value=abcd`

// TODO add false tests too

func TestParser(t *testing.T) {
	tests := strings.Split(samples, "\n")
	for _, test := range tests {
		pk11uri := RFC7512Parser(test)
		if len(pk11uri.Id) == 0 {
			t.Fail()
		}
	}
}
