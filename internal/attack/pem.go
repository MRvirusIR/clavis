package attack

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func privKeyPEM(priv *rsa.PrivateKey) string {
	der := x509.MarshalPKCS1PrivateKey(priv)
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	return string(b)
}
