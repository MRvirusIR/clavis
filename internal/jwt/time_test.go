package jwt

import (
	"testing"
	"time"
)

func TestRelTime(t *testing.T) {
	timeNow = func() time.Time { return time.Unix(1000, 0) }
	defer func() { timeNow = time.Now }()

	cases := map[string]int64{
		"+1h":  1000 + 3600,
		"-30m": 1000 - 1800,
		"+7d":  1000 + 7*86400,
		"+90s": 1000 + 90,
	}
	for in, want := range cases {
		got, ok := relTime(in)
		if !ok || got != want {
			t.Fatalf("relTime(%q) = %d,%v want %d", in, got, ok, want)
		}
	}
	if _, ok := relTime("admin"); ok {
		t.Fatal("non-relative string must return ok=false")
	}
}

func TestParseKVAppliesRelativeExp(t *testing.T) {
	timeNow = func() time.Time { return time.Unix(1000, 0) }
	defer func() { timeNow = time.Now }()
	m := ParseKV([]string{"exp=+1h", "role=admin"})
	if m["exp"] != int64(1000+3600) {
		t.Fatalf("exp = %v", m["exp"])
	}
	if m["role"] != "admin" {
		t.Fatalf("role = %v", m["role"])
	}
}
