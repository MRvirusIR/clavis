package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/MRvirusIR/clavis/internal/jwt"
)

// readToken resolves a token from -t, a positional arg, @file, or stdin.
func readToken(tokFlag string, rest []string) (string, error) {
	cand := strings.TrimSpace(tokFlag)
	if cand == "" && len(rest) > 0 {
		cand = strings.TrimSpace(rest[0])
	}
	if cand == "" {
		fi, _ := os.Stdin.Stat()
		if (fi.Mode() & os.ModeCharDevice) == 0 {
			b, _ := io.ReadAll(os.Stdin)
			cand = strings.TrimSpace(string(b))
		}
	}
	if strings.HasPrefix(cand, "@") {
		b, err := os.ReadFile(cand[1:])
		if err != nil {
			return "", err
		}
		cand = strings.TrimSpace(string(b))
	}
	if cand == "" {
		return "", fmt.Errorf("no token provided (use -t <jwt>, a file with @path, or pipe via stdin)")
	}
	return cand, nil
}

// mustParse parses or prints a friendly error and returns nil.
func mustParse(raw string) *jwt.Token {
	t, err := jwt.Parse(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return nil
	}
	return t
}

// multiSet collects repeatable -set k=v flags.
type multiSet []string

func (m *multiSet) String() string { return strings.Join(*m, ",") }
func (m *multiSet) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func printToken(tok string) { fmt.Println(tok) }
