package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/MRvirusIR/clavis/internal/crack"
	"github.com/MRvirusIR/clavis/internal/jwt"
	"github.com/MRvirusIR/clavis/internal/ui"
	"github.com/MRvirusIR/clavis/internal/words"
)

func cmdCrack(args []string) int {
	fs := flag.NewFlagSet("crack", flag.ContinueOnError)
	tok := fs.String("t", "", "HS* JWT to crack")
	wl := fs.String("w", "", "wordlist file (defaults to built-in common secrets)")
	brute := fs.String("brute", "", "brute-force charset (e.g. abc123); enables brute mode")
	maxLen := fs.Int("max", 6, "max length for brute mode")
	workers := fs.Int("threads", runtime.NumCPU(), "concurrent workers")
	noBuiltin := fs.Bool("no-builtin", false, "skip the built-in common-secrets pass")
	quiet := fs.Bool("quiet", false, "no progress output")
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
	if !strings.HasPrefix(t.Alg(), "HS") {
		ui.Bad("crack only works on HS* tokens; this token is %q", t.Alg())
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var prog crack.Progress
	if !*quiet {
		prog = func(n uint64, last string) {
			fmt.Fprintf(os.Stderr, "\r%s %d tried  (last: %-20.20s)", ui.Dim("[*]"), n, last)
		}
	}

	if *brute == "" && !*noBuiltin {
		for _, w := range words.Common {
			if jwt.VerifyHMAC(t.Alg(), t.SigningInput(), []byte(w), t.Sig) {
				ui.OK("secret found in built-in list: %s", ui.Bold(w))
				fmt.Println(w)
				return 0
			}
		}
		ui.Info("built-in list (%d) exhausted", len(words.Common))
	}

	if *brute != "" {
		ui.Info("brute-forcing charset %q up to length %d with %d workers", *brute, *maxLen, *workers)
		res := crack.Brute(ctx, t, *brute, *maxLen, *workers, prog)
		fmt.Fprintln(os.Stderr)
		return report(res.Found, res.Secret, res.Tried, res.Elapsed.Seconds())
	}

	if *wl == "" {
		ui.Warn("not in built-in list; pass a wordlist with -w rockyou.txt or brute with -brute")
		return 1
	}
	ui.Info("cracking with %s using %d workers", *wl, *workers)
	res, err := crack.Wordlist(ctx, t, *wl, *workers, prog)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		ui.Bad(err.Error())
		return 2
	}
	return report(res.Found, res.Secret, res.Tried, res.Elapsed.Seconds())
}

func report(found bool, secret string, tried uint64, secs float64) int {
	rate := float64(tried)
	if secs > 0 {
		rate = float64(tried) / secs
	}
	if found {
		ui.OK("SECRET FOUND: %s", ui.Bold(secret))
		ui.Info("tried %d candidates in %.2fs (%.0f/s)", tried, secs, rate)
		fmt.Println(secret)
		return 0
	}
	ui.Bad("secret not found after %d candidates (%.2fs, %.0f/s)", tried, secs, rate)
	return 1
}
