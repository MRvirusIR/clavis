package scan

import "testing"

func TestFindString(t *testing.T) {
	txt := `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc
	noise eyJhbGciOiJub25lIn0.eyJhIjoxfQ. end
	dup eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc`
	got := FindString(txt)
	if len(got) != 2 {
		t.Fatalf("want 2 unique tokens, got %d: %v", len(got), got)
	}
}
