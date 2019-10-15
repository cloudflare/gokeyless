// +build pkcs11,cgo

package rfc7512

import (
	"strings"
	"testing"
)

var samples = `pkcs11:id=0
pkcs11:id=0;token=b
pkcs11:id=b?pin-value=1234
pkcs11:id=b?pin-value=1234&module-path=/a/b.so
pkcs11:id=b;token=b?pin-value=1234&module-path=/a/b.so
pkcs11:token=Thalesn6000;id=%00?module-path=/opt/nfast/toolkits/pkcs11/libcknfast.so&pin-value=1234
pkcs11:token=SoftHSM2;id=%00;slot-id=1359138056?module-path=/usr/lib64/libsofthsm2.so&pin-value=1234
pkcs11:token=YubiKey%20PIV;id=%00;slot-id=0?module-path=/usr/lib64/libykcs11.so&pin-value=123456
pkcs11:token=Gemalto;id=%04;slot-id=0?module-path=/usr/lib/libCryptoki2_64.so&pin-value=abcd
pkcs11:token=A;manufacturer=B;serial=C;model=D;library-manufacturer=E;library-description=F;library-version=G;object=H;type=I;id=J;slot-manufacturer=K;slot-description=L;slot-id=0?pin-source=N&pin-value=O&module-name=P&module-path=Q&max-sessions=1`

var negatives = `pkcs11:
pkcs12:id=0
pkcs11:id=b?pin-value=1234;module-path=/a/b.so`

func TestParsePKCS11URI(t *testing.T) {
	tests := strings.Split(samples, "\n")
	for _, uri := range tests {
		if _, err := ParsePKCS11URI(uri); err != nil {
			t.Fatal(err)
		}
	}
	tests = strings.Split(negatives, "\n")
	for _, uri := range tests {
		if _, err := ParsePKCS11URI(uri); err == nil {
			t.Fatalf("PKCS#11 Parser failed to detect a wrong URI: %s", uri)
		}
	}
}
