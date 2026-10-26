package jwt

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// orderedJSON marshals a map but keeps a stable, readable key order so forged
// tokens look natural (typ/alg first for headers; common claims first for payloads).
func orderedJSON(m map[string]any, priority []string) string {
	seen := map[string]bool{}
	var b strings.Builder
	b.WriteByte('{')
	first := true
	write := func(k string) {
		v, ok := m[k]
		if !ok || seen[k] {
			return
		}
		seen[k] = true
		if !first {
			b.WriteByte(',')
		}
		first = false
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(v)
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	for _, k := range priority {
		write(k)
	}
	rest := make([]string, 0, len(m))
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		write(k)
	}
	b.WriteByte('}')
	return b.String()
}

// EncodeHeader builds a base64url JOSE header.
func EncodeHeader(h map[string]any) string {
	return B64([]byte(orderedJSON(h, []string{"typ", "alg", "kid", "jku", "jwk", "x5u", "x5c"})))
}

// EncodeClaims builds a base64url payload.
func EncodeClaims(c map[string]any) string {
	return B64([]byte(orderedJSON(c, []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "name", "user", "username", "email", "role", "admin"})))
}

// Build assembles header.claims.sig, computing the signature per alg/key.
// For alg=none, key is ignored and the signature is empty.
func Build(header, claims map[string]any, key []byte) (string, error) {
	alg, _ := header["alg"].(string)
	alg = strings.ToUpper(alg)
	hp := EncodeHeader(header)
	cp := EncodeClaims(claims)
	si := hp + "." + cp

	switch {
	case alg == "NONE" || alg == "":
		return si + ".", nil
	case strings.HasPrefix(alg, "HS"):
		sig, err := SignHMAC(alg, si, key)
		if err != nil {
			return "", err
		}
		return si + "." + sig, nil
	case strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS"):
		priv, err := ParseRSAPrivate(key)
		if err != nil {
			return "", fmt.Errorf("RSA sign needs a private key: %w", err)
		}
		sig, err := SignRSA(alg, si, priv)
		if err != nil {
			return "", err
		}
		return si + "." + sig, nil
	}
	return "", fmt.Errorf("Build: unsupported alg %q (use HS*, RS*, PS* or none)", alg)
}

// CloneMap returns a shallow copy so edits don't mutate the source token.
func CloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ParseKV parses "k=v" edits into a map, turning true/false/numbers/null into typed JSON.
// Relative time values are supported for time-like claims: +1h, -30m, +7d (seconds from now).
func ParseKV(pairs []string) map[string]any {
	out := map[string]any{}
	for _, p := range pairs {
		i := strings.IndexByte(p, '=')
		if i < 0 {
			continue
		}
		k, raw := p[:i], p[i+1:]
		if isTimeClaim(k) {
			if ts, ok := relTime(raw); ok {
				out[k] = ts
				continue
			}
		}
		out[k] = coerce(raw)
	}
	return out
}

func isTimeClaim(k string) bool {
	switch k {
	case "exp", "nbf", "iat", "auth_time":
		return true
	}
	return false
}

func coerce(s string) any {
	switch strings.ToLower(s) {
	case "true":
		return true
	case "false":
		return false
	case "null":
		return nil
	}
	var n json.Number
	if err := json.Unmarshal([]byte(s), &n); err == nil {
		if i, err := n.Int64(); err == nil {
			return i
		}
		if f, err := n.Float64(); err == nil {
			return f
		}
	}
	if (strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")) ||
		(strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]")) {
		var v any
		if err := json.Unmarshal([]byte(s), &v); err == nil {
			return v
		}
	}
	return s
}
