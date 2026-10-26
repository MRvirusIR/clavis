package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/MRvirusIR/clavis/internal/audit"
	"github.com/MRvirusIR/clavis/internal/ui"
)

func cmdAudit(args []string) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	tok := fs.String("t", "", "JWT to audit (or positional, @file, or stdin)")
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

	ui.Section("token")
	ui.Field("alg", t.Alg())
	if t.Claims != nil {
		if sub, ok := t.Claims["sub"]; ok {
			ui.Field("sub", fmt.Sprintf("%v", sub))
		}
	}

	findings := audit.Run(t, time.Now())
	ui.Section(fmt.Sprintf("findings (%d)", len(findings)))
	if len(findings) == 0 {
		ui.OK("no obvious issues found")
		return 0
	}
	worst := audit.Info
	for _, f := range findings {
		printFinding(f)
		if f.Sev > worst {
			worst = f.Sev
		}
	}
	fmt.Println()
	switch {
	case worst >= audit.Critical:
		ui.Bad("worst severity: CRITICAL — this token is likely forgeable")
	case worst >= audit.High:
		ui.Warn("worst severity: HIGH")
	default:
		ui.Info("worst severity: %s", worst.String())
	}
	return 0
}

func printFinding(f audit.Finding) {
	var tag string
	switch f.Sev {
	case audit.Critical:
		tag = ui.Red("● CRITICAL")
	case audit.High:
		tag = ui.Red("● HIGH")
	case audit.Medium:
		tag = ui.Yellow("● MEDIUM")
	case audit.Low:
		tag = ui.Blue("● LOW")
	default:
		tag = ui.Dim("● INFO")
	}
	fmt.Printf("  %s  %s\n", tag, ui.Bold(f.Title))
	fmt.Printf("      %s\n", ui.Dim(f.Desc))
	if f.Hint != "" {
		fmt.Printf("      %s %s\n", ui.Green("↳"), f.Hint)
	}
}
