package crack

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MRvirusIR/clavis/internal/jwt"
)

func TestWordlistFindsSecret(t *testing.T) {
	built, _ := jwt.Build(map[string]any{"alg": "HS256", "typ": "JWT"}, map[string]any{"sub": "1"}, []byte("letmein"))
	tok, _ := jwt.Parse(built)

	dir := t.TempDir()
	wl := filepath.Join(dir, "w.txt")
	os.WriteFile(wl, []byte("foo\nbar\nletmein\nbaz\n"), 0o600)

	res, err := Wordlist(context.Background(), tok, wl, 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Found || res.Secret != "letmein" {
		t.Fatalf("expected to find letmein, got %+v", res)
	}
}

func TestBruteFindsShortSecret(t *testing.T) {
	built, _ := jwt.Build(map[string]any{"alg": "HS256", "typ": "JWT"}, map[string]any{"sub": "1"}, []byte("ac"))
	tok, _ := jwt.Parse(built)
	res := Brute(context.Background(), tok, "abc", 2, 4, nil)
	if !res.Found || res.Secret != "ac" {
		t.Fatalf("expected to brute ac, got %+v", res)
	}
}
