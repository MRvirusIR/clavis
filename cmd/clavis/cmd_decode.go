package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/MRvirusIR/clavis/internal/ui"
)

func cmdDecode(args []string) int {
	fs := flag.NewFlagSet("decode", flag.ContinueOnError)
	tok := fs.String("t", "", "JWT to decode (or positional, @file, or stdin)")
	raw := fs.Bool("raw", false, "print raw decoded JSON only (no colors/sections)")
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
	if *raw {
		fmt.Println(t.PrettyHeader())
		fmt.Println(t.PrettyClaims())
		return 0
	}

	ui.Section("header")
	fmt.Println(t.PrettyHeader())
	ui.Section("payload")
	fmt.Println(t.PrettyClaims())
	ui.Section("signature")
	ui.Field("alg", t.Alg())
	ui.Field("bytes", fmt.Sprintf("%d", len(t.Sig)))

	if t.Claims != nil {
		shown := false
		for _, k := range []string{"iat", "nbf", "exp", "auth_time", "updated_at"} {
			if v, ok := t.Claims[k]; ok {
				if f, ok := toFloat(v); ok {
					if !shown {
						ui.Section("timestamps")
						shown = true
					}
					ts := time.Unix(int64(f), 0).UTC().Format("2006-01-02 15:04:05 MST")
					rel := humanize(time.Until(time.Unix(int64(f), 0)))
					ui.Field(k, fmt.Sprintf("%s  (%s)", ts, rel))
				}
			}
		}
	}
	return 0
}

func toFloat(v any) (float64, bool) {
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

func humanize(d time.Duration) string {
	if d < 0 {
		return "expired " + dur(-d) + " ago"
	}
	return "in " + dur(d)
}

func dur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%.1fh", d.Hours())
	default:
		return fmt.Sprintf("%.1fd", d.Hours()/24)
	}
}
