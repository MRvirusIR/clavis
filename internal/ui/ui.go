// Package ui provides small terminal helpers: colors (respecting NO_COLOR),
// the banner, and labeled lines. No dependencies.
package ui

import (
	"fmt"
	"os"
	"strings"
)

var NoColor = os.Getenv("NO_COLOR") != ""

const (
	reset = "\033[0m"
	dim   = "\033[2m"
	bold  = "\033[1m"
	red   = "\033[31m"
	grn   = "\033[32m"
	yel   = "\033[33m"
	blu   = "\033[34m"
	mag   = "\033[35m"
	cyn   = "\033[36m"
)

func c(code, s string) string {
	if NoColor {
		return s
	}
	return code + s + reset
}

func Cyan(s string) string   { return c(cyn, s) }
func Green(s string) string  { return c(grn, s) }
func Yellow(s string) string { return c(yel, s) }
func Red(s string) string    { return c(red, s) }
func Blue(s string) string   { return c(blu, s) }
func Mag(s string) string    { return c(mag, s) }
func Dim(s string) string    { return c(dim, s) }
func Bold(s string) string   { return c(bold, s) }

const Banner = `
   ██████╗██╗      █████╗ ██╗   ██╗██╗███████╗
  ██╔════╝██║     ██╔══██╗██║   ██║██║██╔════╝
  ██║     ██║     ███████║██║   ██║██║███████╗
  ██║     ██║     ██╔══██║╚██╗ ██╔╝██║╚════██║
  ╚██████╗███████╗██║  ██║ ╚████╔╝ ██║███████║
   ╚═════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚══════╝`

const Tagline = "  The JWT multitool for bug bounty  ·  v%s\n  t.me/BugCod3   ·   github.com/MRvirusIR/clavis\n"

// PrintBanner writes the banner to stderr.
func PrintBanner(version string) {
	fmt.Fprint(os.Stderr, Cyan(Banner)+"\n")
	fmt.Fprint(os.Stderr, Dim(fmt.Sprintf(Tagline, version)))
}

// Field prints "  label : value" aligned.
func Field(label, value string) {
	fmt.Printf("  %s %s\n", Dim(pad(label, 10)+":"), value)
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// Section prints a dim header like "── header ─────".
func Section(title string) {
	line := "── " + title + " "
	if len(line) < 56 {
		line += strings.Repeat("─", 56-len(line))
	}
	fmt.Println(Dim(line))
}

// OK / Warn / Bad / Info print status lines to stderr.
func OK(f string, a ...any)   { fmt.Fprintln(os.Stderr, Green("[+] ")+fmt.Sprintf(f, a...)) }
func Warn(f string, a ...any) { fmt.Fprintln(os.Stderr, Yellow("[!] ")+fmt.Sprintf(f, a...)) }
func Bad(f string, a ...any)  { fmt.Fprintln(os.Stderr, Red("[-] ")+fmt.Sprintf(f, a...)) }
func Info(f string, a ...any) { fmt.Fprintln(os.Stderr, Blue("[*] ")+fmt.Sprintf(f, a...)) }
