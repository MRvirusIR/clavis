package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/MRvirusIR/clavis/internal/audit"
	"github.com/MRvirusIR/clavis/internal/jwt"
	"github.com/MRvirusIR/clavis/internal/scan"
	"github.com/MRvirusIR/clavis/internal/ui"
)

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	file := fs.String("f", "", "file to scan for JWTs (default: stdin)")
	doAudit := fs.Bool("audit", false, "audit every token found")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var r *os.File
	if *file != "" {
		f, err := os.Open(*file)
		if err != nil {
			ui.Bad(err.Error())
			return 2
		}
		defer f.Close()
		r = f
	} else {
		r = os.Stdin
	}

	tokens := scan.Find(r)
	if len(tokens) == 0 {
		ui.Warn("no JWTs found")
		return 1
	}
	ui.OK("found %d JWT(s)", len(tokens))
	for i, tk := range tokens {
		ui.Section(fmt.Sprintf("#%d", i+1))
		fmt.Println(tk)
		t, err := jwt.Parse(tk)
		if err != nil {
			ui.Bad("  parse: %v", err)
			continue
		}
		ui.Field("alg", t.Alg())
		if t.Claims != nil {
			if sub, ok := t.Claims["sub"]; ok {
				ui.Field("sub", fmt.Sprintf("%v", sub))
			}
		}
		if *doAudit {
			worst := audit.Info
			for _, f := range audit.Run(t, time.Now()) {
				if f.Sev > worst {
					worst = f.Sev
				}
			}
			ui.Field("worst", worst.String())
		}
	}
	return 0
}
