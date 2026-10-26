package main

import (
	"flag"
	"os"
	"strings"

	"github.com/MRvirusIR/clavis/internal/jwt"
	"github.com/MRvirusIR/clavis/internal/ui"
)

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	tok := fs.String("t", "", "JWT to verify")
	secret := fs.String("secret", "", "HMAC secret for HS*")
	pubFile := fs.String("pub", "", "public key file (PEM/JWK) for RS*/ES*/PS*")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	tk, err := readToken(*tok, fs.Args())
	if err != nil {
		ui.Bad(err.Error())
		return 2
	}
	t := mustParse(tk)
	if t == nil {
		return 1
	}
	alg := t.Alg()
	ok := false
	switch {
	case strings.HasPrefix(alg, "HS"):
		if *secret == "" {
			ui.Bad("HS* needs -secret")
			return 2
		}
		ok = jwt.VerifyHMAC(alg, t.SigningInput(), []byte(*secret), t.Sig)
	case strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS"):
		if *pubFile == "" {
			ui.Bad("%s needs -pub", alg)
			return 2
		}
		data, err := os.ReadFile(*pubFile)
		if err != nil {
			ui.Bad(err.Error())
			return 2
		}
		pub, err := jwt.ParseRSAPublic(data)
		if err != nil {
			ui.Bad(err.Error())
			return 2
		}
		ok = jwt.VerifyRSA(alg, t.SigningInput(), pub, t.Sig)
	case strings.HasPrefix(alg, "ES"):
		if *pubFile == "" {
			ui.Bad("%s needs -pub", alg)
			return 2
		}
		data, err := os.ReadFile(*pubFile)
		if err != nil {
			ui.Bad(err.Error())
			return 2
		}
		pub, err := jwt.ParseECPublic(data)
		if err != nil {
			ui.Bad(err.Error())
			return 2
		}
		ok = jwt.VerifyECDSA(alg, t.SigningInput(), pub, t.Sig)
	default:
		ui.Bad("cannot verify alg %q", alg)
		return 2
	}
	if ok {
		ui.OK("signature VALID (%s)", alg)
		return 0
	}
	ui.Bad("signature INVALID (%s)", alg)
	return 1
}
