package main

import (
	"flag"
	"os"
	"strings"

	"github.com/MRvirusIR/clavis/internal/jwt"
	"github.com/MRvirusIR/clavis/internal/ui"
)

func cmdForge(args []string) int {
	var sets multiSet
	var hsets multiSet
	fs := flag.NewFlagSet("forge", flag.ContinueOnError)
	tok := fs.String("t", "", "base JWT to start from (optional)")
	alg := fs.String("alg", "", "signing alg (HS256/HS384/HS512/RS256/.../none)")
	secret := fs.String("secret", "", "HMAC secret for HS*")
	keyFile := fs.String("key", "", "RSA private key file (PEM) for RS*/PS*")
	fs.Var(&sets, "set", "set a claim: -set role=admin (repeatable; k=DELETE removes; exp=+1h for relative time)")
	fs.Var(&hsets, "header", "set a header field: -header kid=1 (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	header := map[string]any{"typ": "JWT", "alg": "HS256"}
	claims := map[string]any{}
	if strings.TrimSpace(*tok) != "" || len(fs.Args()) > 0 {
		if tk, err := readToken(*tok, fs.Args()); err == nil {
			if base := mustParse(tk); base != nil {
				header = jwt.CloneMap(base.Header)
				if base.Claims != nil {
					claims = jwt.CloneMap(base.Claims)
				}
			}
		}
	}
	if *alg != "" {
		header["alg"] = *alg
	}
	for k, v := range jwt.ParseKV(hsets) {
		header[k] = v
	}
	for k, v := range jwt.ParseKV(sets) {
		if s, ok := v.(string); ok && s == "DELETE" {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}

	a := strings.ToUpper(header["alg"].(string))
	var key []byte
	switch {
	case a == "NONE":
	case strings.HasPrefix(a, "HS"):
		key = []byte(*secret)
		if *secret == "" {
			ui.Warn("no -secret given; signing with empty key")
		}
	case strings.HasPrefix(a, "RS") || strings.HasPrefix(a, "PS"):
		if *keyFile == "" {
			ui.Bad("%s needs -key <private.pem>", a)
			return 2
		}
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			ui.Bad(err.Error())
			return 2
		}
		key = b
	default:
		ui.Bad("unsupported alg %q", a)
		return 2
	}

	tokStr, err := jwt.Build(header, claims, key)
	if err != nil {
		ui.Bad(err.Error())
		return 1
	}
	ui.OK("forged %s token", a)
	printToken(tokStr)
	return 0
}
