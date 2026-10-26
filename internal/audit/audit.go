// Package audit inspects a parsed JWT for common misconfigurations and
// bug-bounty-relevant weaknesses, producing a ranked list of findings.
package audit

import (
	"fmt"
	"strings"
	"time"

	"github.com/MRvirusIR/clavis/internal/jwt"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "CRITICAL"
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	case Low:
		return "LOW"
	default:
		return "INFO"
	}
}

type Finding struct {
	Sev   Severity
	Title string
	Desc  string
	Hint  string // what an attacker/tester should try next
}

// Run performs all static checks against t. now is injectable for tests.
func Run(t *jwt.Token, now time.Time) []Finding {
	var f []Finding
	if t == nil {
		return f
	}
	alg := t.Alg()

	// --- Algorithm checks ---
	switch {
	case alg == "NONE":
		f = append(f, Finding{Critical, "alg=none accepted by this token",
			"The header declares the 'none' algorithm, meaning the token carries no signature.",
			"If the server verifies it, forge any claims with: clavis alg-none -t <token> -set role=admin"})
	case alg == "":
		f = append(f, Finding{High, "Missing alg header",
			"No 'alg' field present. Some libraries default to insecure behaviour.",
			"Try forging with alg=none and with HS256 using an empty/guessable key."})
	case strings.HasPrefix(alg, "HS"):
		f = append(f, Finding{Medium, "HMAC algorithm (" + alg + ")",
			"HS* tokens are signed with a shared secret. If the secret is weak it can be brute-forced offline.",
			"Run: clavis crack -t <token> -w rockyou.txt"})
	case strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "ES") || strings.HasPrefix(alg, "PS"):
		f = append(f, Finding{Info, "Asymmetric algorithm (" + alg + ")",
			"Signed with a private key; verified with the public key.",
			"If you can obtain the public key, test the RS256→HS256 confusion: clavis confuse -t <token> -pub key.pem -set role=admin"})
	default:
		f = append(f, Finding{Medium, "Unusual algorithm (" + alg + ")",
			"Non-standard algorithm value.", "Check how the server handles unknown algs."})
	}

	// --- Header-injection vectors ---
	if v, ok := t.Header["jku"]; ok {
		f = append(f, Finding{High, "jku header present",
			fmt.Sprintf("'jku' points the verifier at a JWKS URL (%v). If not allow-listed, the server may fetch attacker-hosted keys.", v),
			"Host your own JWKS and point jku at it: clavis jku-inject -t <token> -jku https://you/.well-known/jwks.json -set role=admin"})
	}
	if _, ok := t.Header["jwk"]; ok {
		f = append(f, Finding{Critical, "Embedded jwk in header",
			"The token embeds its own public key. Vulnerable verifiers trust this key directly (CVE-2018-0114 class).",
			"Use: clavis jwk-inject -t <token> -set role=admin"})
	}
	if v, ok := t.Header["kid"]; ok {
		ks := fmt.Sprintf("%v", v)
		f = append(f, Finding{Medium, "kid header present",
			fmt.Sprintf("'kid' = %q is often concatenated into a file path or SQL query.", ks),
			"Test path traversal & SQLi: clavis kid-inject -t <token> -kid '../../dev/null' -key '' -set role=admin"})
	}
	if _, ok := t.Header["x5u"]; ok {
		f = append(f, Finding{High, "x5u header present",
			"'x5u' references an external X.509 cert URL, another SSRF/key-injection vector.",
			"Point x5u at a cert you control if it is not allow-listed."})
	}
	if _, ok := t.Header["x5c"]; ok {
		f = append(f, Finding{High, "x5c header present",
			"'x5c' embeds an X.509 cert chain. Some verifiers trust it directly, like jwk.",
			"Craft a self-signed cert chain and sign with its key."})
	}

	// --- Claim checks ---
	c := t.Claims
	if c != nil {
		if exp, ok := num(c["exp"]); ok {
			et := time.Unix(int64(exp), 0).UTC()
			if et.Before(now) {
				f = append(f, Finding{Low, "Token is expired",
					"exp is in the past (" + et.Format("2006-01-02 15:04 MST") + ").",
					"Expired tokens sometimes still work — replay it to check exp enforcement."})
			}
			if exp-float64(now.Unix()) > 60*60*24*365 {
				f = append(f, Finding{Low, "Very long-lived token",
					"exp is more than a year away, widening the replay window if stolen.", ""})
			}
		} else {
			f = append(f, Finding{Medium, "No exp claim",
				"The token never expires, widening the window for replay/theft.",
				"Report missing expiry; test whether old tokens stay valid forever."})
		}
		if _, ok := c["iat"]; !ok {
			f = append(f, Finding{Info, "No iat claim", "No issued-at timestamp.", ""})
		}
		for _, k := range []string{"admin", "is_admin", "isAdmin", "role", "roles", "scope", "scopes", "groups", "permissions", "superuser", "is_staff", "isAdministrator"} {
			if v, ok := c[k]; ok {
				f = append(f, Finding{Info, "Privilege claim: " + k,
					fmt.Sprintf("Authorization appears to depend on %q = %v inside the token.", k, v),
					"If you can forge the signature, escalate by editing this claim."})
			}
		}
	} else {
		f = append(f, Finding{Low, "Claims are not a JSON object",
			"The payload did not decode to a JSON object.", ""})
	}

	sortFindings(f)
	return f
}

func num(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	}
	return 0, false
}

func sortFindings(f []Finding) {
	for i := 1; i < len(f); i++ {
		for j := i; j > 0 && f[j].Sev > f[j-1].Sev; j-- {
			f[j], f[j-1] = f[j-1], f[j]
		}
	}
}
