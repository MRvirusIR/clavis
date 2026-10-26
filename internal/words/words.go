// Package words ships a small built-in list of the HMAC secrets most commonly
// found in tutorials, boilerplates and leaked configs. It is a fast first pass
// before reaching for rockyou.txt.
package words

// Common is deduplicated at init time.
var Common = []string{
	"secret", "secretkey", "secret_key", "secretKey", "your-256-bit-secret",
	"your-secret-key", "changeme", "change_me", "password", "passw0rd",
	"admin", "root", "test", "testing", "dev", "development", "prod",
	"jwt", "jwtsecret", "jwt_secret", "jwtSecret", "jwtkey", "jwt_key",
	"token", "tokensecret", "mysecret", "mysecretkey", "supersecret",
	"supersecretkey", "topsecret", "key", "private", "privatekey",
	"s3cr3t", "s3cret", "qwerty", "123456", "1234567890", "0000",
	"hello", "helloworld", "foo", "bar", "foobar", "example",
	"HS256", "default", "defaultsecret", "app", "appsecret", "api",
	"apisecret", "api_secret", "shhhh", "shh", "letmein", "iloveyou",
	"ThisIsASecret", "VerySecret", "my_super_secret", "P@ssw0rd",
	"node", "express", "django", "flask", "laravel", "spring",
	"NDE2", "secret123", "admin123", "password123", "welcome",
	"xxxxxxxx", "00000000", "abcdefgh", "aaaaaaaa", "secretsecret",
	"your_jwt_secret", "YOUR_SECRET_KEY", "JWT_SECRET", "SECRET_KEY",
	"my-secret", "the-secret", "super-secret", "ultra-secret",
	"bugcod3", "BugCod3", "hackme", "h4ck3r", "pentest", "bugbounty",
}

func init() {
	seen := map[string]bool{}
	out := Common[:0]
	for _, w := range Common {
		if !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
	}
	Common = out
}
