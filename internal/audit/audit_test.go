package audit

import (
	"testing"
	"time"

	"github.com/MRvirusIR/clavis/internal/jwt"
)

func sev(fs []Finding, title string) (Severity, bool) {
	for _, f := range fs {
		if f.Title == title {
			return f.Sev, true
		}
	}
	return Info, false
}

func TestAlgNoneCritical(t *testing.T) {
	tok, _ := jwt.Parse("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.")
	fs := Run(tok, time.Now())
	if s, ok := sev(fs, "alg=none accepted by this token"); !ok || s != Critical {
		t.Fatalf("expected critical alg=none, got %v %v", s, ok)
	}
}

func TestEmbeddedJWKCritical(t *testing.T) {
	tok, _ := jwt.Parse("eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EifX0.eyJzdWIiOiIxIn0.AAAA")
	fs := Run(tok, time.Now())
	if s, ok := sev(fs, "Embedded jwk in header"); !ok || s != Critical {
		t.Fatalf("expected critical embedded jwk, got %v %v", s, ok)
	}
}

func TestExpiredDetected(t *testing.T) {
	tok, _ := jwt.Parse("eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjF9.AAAA")
	fs := Run(tok, time.Now())
	if _, ok := sev(fs, "Token is expired"); !ok {
		t.Fatal("expected expired finding")
	}
}

func TestNilTokenSafe(t *testing.T) {
	if fs := Run(nil, time.Now()); len(fs) != 0 {
		t.Fatal("nil token should yield no findings")
	}
}
