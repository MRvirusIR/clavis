// Package jwt implements the minimal JOSE primitives Clavis needs:
// base64url parsing, header/claim decoding, and HMAC / RSA / ECDSA signing
// and verification. It deliberately avoids third-party dependencies.
package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Token is a parsed JWT in its three raw parts plus decoded header/claims.
type Token struct {
	Raw       string
	RawHeader string // base64url, no padding
	RawClaims string // base64url, no padding
	RawSig    string // base64url, no padding

	Header map[string]any
	Claims map[string]any
	Sig    []byte
}

// B64 encodes to base64url without padding (JOSE style).
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// UnB64 decodes base64url, tolerating missing padding and the std alphabet.
func UnB64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")
	return base64.RawURLEncoding.DecodeString(s)
}

// Parse splits and decodes a compact JWS. The signature may be empty (alg=none).
func Parse(raw string) (*Token, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "Bearer ")
	raw = strings.TrimPrefix(raw, "bearer ")
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a compact JWT: expected 3 parts, got %d", len(parts))
	}
	t := &Token{Raw: raw, RawHeader: parts[0], RawClaims: parts[1], RawSig: parts[2]}

	hb, err := UnB64(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header is not valid base64url: %w", err)
	}
	if err := json.Unmarshal(hb, &t.Header); err != nil {
		return nil, fmt.Errorf("header is not valid JSON: %w", err)
	}
	cb, err := UnB64(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload is not valid base64url: %w", err)
	}
	// Claims may legitimately be a non-object in weird tokens; keep going if so.
	_ = json.Unmarshal(cb, &t.Claims)

	if parts[2] != "" {
		t.Sig, err = UnB64(parts[2])
		if err != nil {
			return nil, fmt.Errorf("signature is not valid base64url: %w", err)
		}
	}
	return t, nil
}

// Alg returns the normalized algorithm from the header (upper-case).
func (t *Token) Alg() string {
	if v, ok := t.Header["alg"].(string); ok {
		return strings.ToUpper(v)
	}
	return ""
}

// SigningInput is the "header.claims" string that the signature covers.
func (t *Token) SigningInput() string { return t.RawHeader + "." + t.RawClaims }

// PrettyHeader / PrettyClaims return indented JSON for display.
func (t *Token) PrettyHeader() string { return pretty(t.Header) }
func (t *Token) PrettyClaims() string {
	if t.Claims == nil {
		b, _ := UnB64(t.RawClaims)
		return string(b)
	}
	return pretty(t.Claims)
}

func pretty(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

// --- Signing ---------------------------------------------------------------

func hasher(alg string) (crypto.Hash, func() []byte, error) {
	switch alg {
	case "HS256", "RS256", "ES256", "PS256":
		h := sha256.New()
		return crypto.SHA256, func() []byte { return h.Sum(nil) }, nil
	case "HS384", "RS384", "ES384", "PS384":
		h := sha512.New384()
		return crypto.SHA384, func() []byte { return h.Sum(nil) }, nil
	case "HS512", "RS512", "ES512", "PS512":
		h := sha512.New()
		return crypto.SHA512, func() []byte { return h.Sum(nil) }, nil
	}
	return 0, nil, fmt.Errorf("unsupported alg %q", alg)
}

// SignHMAC returns the base64url HMAC signature for signingInput using key.
func SignHMAC(alg, signingInput string, key []byte) (string, error) {
	var mac interface {
		Write([]byte) (int, error)
		Sum([]byte) []byte
	}
	switch alg {
	case "HS256":
		mac = hmac.New(sha256.New, key)
	case "HS384":
		mac = hmac.New(sha512.New384, key)
	case "HS512":
		mac = hmac.New(sha512.New, key)
	default:
		return "", fmt.Errorf("SignHMAC: unsupported alg %q", alg)
	}
	mac.Write([]byte(signingInput))
	return B64(mac.Sum(nil)), nil
}

// VerifyHMAC reports whether sig is the correct HMAC of signingInput.
func VerifyHMAC(alg, signingInput string, key, sig []byte) bool {
	want, err := SignHMAC(alg, signingInput, key)
	if err != nil {
		return false
	}
	w, _ := UnB64(want)
	return hmac.Equal(w, sig)
}

func digest(h crypto.Hash, data string) []byte {
	hh := h.New()
	hh.Write([]byte(data))
	return hh.Sum(nil)
}

// VerifyRSA verifies an RS*/PS* signature.
func VerifyRSA(alg, signingInput string, pub *rsa.PublicKey, sig []byte) bool {
	h, _, err := hasher(alg)
	if err != nil {
		return false
	}
	sum := digest(h, signingInput)
	if strings.HasPrefix(alg, "PS") {
		return rsa.VerifyPSS(pub, h, sum, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: h}) == nil
	}
	return rsa.VerifyPKCS1v15(pub, h, sum, sig) == nil
}

// SignRSA creates an RS*/PS* signature.
func SignRSA(alg, signingInput string, priv *rsa.PrivateKey) (string, error) {
	h, _, err := hasher(alg)
	if err != nil {
		return "", err
	}
	sum := digest(h, signingInput)
	var sig []byte
	if strings.HasPrefix(alg, "PS") {
		sig, err = rsa.SignPSS(randReader, priv, h, sum, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: h})
	} else {
		sig, err = rsa.SignPKCS1v15(randReader, priv, h, sum)
	}
	if err != nil {
		return "", err
	}
	return B64(sig), nil
}

// VerifyECDSA verifies an ES* signature (raw r||s form).
func VerifyECDSA(alg, signingInput string, pub *ecdsa.PublicKey, sig []byte) bool {
	h, _, err := hasher(alg)
	if err != nil {
		return false
	}
	n := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*n {
		return false
	}
	r := new(big.Int).SetBytes(sig[:n])
	s := new(big.Int).SetBytes(sig[n:])
	sum := digest(h, signingInput)
	return ecdsa.Verify(pub, sum, r, s)
}

var errNoClaims = errors.New("token has no decodable claims")

// ClaimsBytes returns the raw decoded claims JSON.
func (t *Token) ClaimsBytes() ([]byte, error) {
	b, err := UnB64(t.RawClaims)
	if err != nil {
		return nil, errNoClaims
	}
	return b, nil
}
