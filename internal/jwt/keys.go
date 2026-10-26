package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
)

var randReader = rand.Reader

// LoadKeyFile reads a PEM or JWK key from disk (public or private).
func LoadKeyFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// ParseRSAPublic accepts PEM (PKIX/PKCS1/CERTIFICATE) or a JWK and returns an RSA public key.
func ParseRSAPublic(data []byte) (*rsa.PublicKey, error) {
	if k, err := parsePublicPEM(data); err == nil {
		if rk, ok := k.(*rsa.PublicKey); ok {
			return rk, nil
		}
		return nil, errors.New("PEM key is not RSA")
	}
	if jk, err := parseJWK(data); err == nil {
		if rk, ok := jk.(*rsa.PublicKey); ok {
			return rk, nil
		}
	}
	return nil, errors.New("could not parse RSA public key (want PEM or JWK)")
}

// ParseECPublic accepts PEM or JWK and returns an ECDSA public key.
func ParseECPublic(data []byte) (*ecdsa.PublicKey, error) {
	if k, err := parsePublicPEM(data); err == nil {
		if ek, ok := k.(*ecdsa.PublicKey); ok {
			return ek, nil
		}
		return nil, errors.New("PEM key is not ECDSA")
	}
	if jk, err := parseJWK(data); err == nil {
		if ek, ok := jk.(*ecdsa.PublicKey); ok {
			return ek, nil
		}
	}
	return nil, errors.New("could not parse EC public key")
}

// ParseRSAPrivate accepts PEM PKCS1/PKCS8.
func ParseRSAPrivate(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
	}
	return nil, errors.New("could not parse RSA private key (PKCS1/PKCS8)")
}

func parsePublicPEM(data []byte) (any, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	switch block.Type {
	case "CERTIFICATE":
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return c.PublicKey, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	}
	if k, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return k, nil
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

// PublicToPEM marshals an RSA/EC public key to PKIX PEM — used by the
// RS256→HS256 confusion attack to recover the exact public-key bytes.
func PublicToPEM(pub any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

type jwkDoc struct {
	Keys []json.RawMessage `json:"keys"`
	Kty  string            `json:"kty"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// parseJWK parses a single JWK or a JWKS (first key) into a public key.
func parseJWK(data []byte) (any, error) {
	var doc jwkDoc
	if err := json.Unmarshal(data, &doc); err == nil && len(doc.Keys) > 0 {
		return jwkFromRaw(doc.Keys[0])
	}
	return jwkFromRaw(data)
}

func jwkFromRaw(raw []byte) (any, error) {
	var k jwkKey
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, err
	}
	switch strings.ToUpper(k.Kty) {
	case "RSA":
		nb, err := b64url(k.N)
		if err != nil {
			return nil, fmt.Errorf("jwk n: %w", err)
		}
		eb, err := b64url(k.E)
		if err != nil {
			return nil, fmt.Errorf("jwk e: %w", err)
		}
		e := 0
		for _, b := range eb {
			e = e<<8 | int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
	case "EC":
		return nil, errors.New("EC JWK parsing not supported; export the key as PEM")
	}
	return nil, errors.New("unsupported JWK kty")
}

func b64url(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}
