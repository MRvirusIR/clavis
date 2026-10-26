package jwt

import "testing"

const hs256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MjAwMDAwMDAwMH0.3HTOmeZuAfkKjlezUhdIy_myQfWUWTyU7Vnkq3_vuj8"

func TestParseHS256(t *testing.T) {
	tok, err := Parse(hs256)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Alg() != "HS256" {
		t.Fatalf("alg = %q", tok.Alg())
	}
	if tok.Claims["name"] != "John Doe" {
		t.Fatalf("name = %v", tok.Claims["name"])
	}
	if len(tok.Sig) != 32 {
		t.Fatalf("sig len = %d", len(tok.Sig))
	}
}

func TestParseBearerPrefix(t *testing.T) {
	tok, err := Parse("Bearer " + hs256)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Alg() != "HS256" {
		t.Fatal("bearer prefix not stripped")
	}
}

func TestVerifyHMAC(t *testing.T) {
	tok, _ := Parse(hs256)
	if !VerifyHMAC("HS256", tok.SigningInput(), []byte("secret"), tok.Sig) {
		t.Fatal("expected valid with correct secret")
	}
	if VerifyHMAC("HS256", tok.SigningInput(), []byte("wrong"), tok.Sig) {
		t.Fatal("expected invalid with wrong secret")
	}
}

func TestBuildRoundTrip(t *testing.T) {
	h := map[string]any{"typ": "JWT", "alg": "HS256"}
	c := map[string]any{"sub": "1", "role": "admin"}
	tokStr, err := Build(h, c, []byte("k3y"))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := Parse(tokStr)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyHMAC("HS256", tok.SigningInput(), []byte("k3y"), tok.Sig) {
		t.Fatal("round-trip verify failed")
	}
	if tok.Claims["role"] != "admin" {
		t.Fatalf("role = %v", tok.Claims["role"])
	}
}

func TestBuildNone(t *testing.T) {
	tokStr, err := Build(map[string]any{"alg": "none"}, map[string]any{"a": 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tokStr[len(tokStr)-1] != '.' {
		t.Fatalf("alg=none token must end with empty sig: %q", tokStr)
	}
}

func TestParseKV(t *testing.T) {
	m := ParseKV([]string{"role=admin", "n=5", "ok=true", "x=null", "f=1.5"})
	if m["role"] != "admin" {
		t.Fatal("string coerce")
	}
	if m["n"] != int64(5) {
		t.Fatalf("int coerce: %T %v", m["n"], m["n"])
	}
	if m["ok"] != true {
		t.Fatal("bool coerce")
	}
	if m["x"] != nil {
		t.Fatal("null coerce")
	}
	if m["f"] != 1.5 {
		t.Fatalf("float coerce: %v", m["f"])
	}
}
