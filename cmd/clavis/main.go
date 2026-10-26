// Clavis — the JWT multitool for bug bounty.
// Authorized security testing only.
package main

import (
	"fmt"
	"os"
)

var version = "1.0.0"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "decode", "d":
		return cmdDecode(args[1:])
	case "audit", "scan-token", "a":
		return cmdAudit(args[1:])
	case "verify", "v":
		return cmdVerify(args[1:])
	case "crack", "c":
		return cmdCrack(args[1:])
	case "forge", "sign", "f":
		return cmdForge(args[1:])
	case "alg-none", "none":
		return cmdAlgNone(args[1:])
	case "confuse", "rs2hs":
		return cmdConfuse(args[1:])
	case "jwk-inject", "jwk":
		return cmdJWKInject(args[1:])
	case "jku-inject", "jku":
		return cmdJKUInject(args[1:])
	case "kid-inject", "kid":
		return cmdKidInject(args[1:])
	case "scan", "grep":
		return cmdScan(args[1:])
	case "version", "-v", "--version":
		fmt.Println("clavis", version)
		return 0
	case "help", "-h", "--help", "h":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage()
		return 2
	}
}
