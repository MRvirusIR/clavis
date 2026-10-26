// Package scan extracts JWT-looking strings from arbitrary text (HTTP logs,
// HAR files, JS bundles, .env dumps) so testers can triage tokens in bulk.
package scan

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

// jwtRe matches three base64url segments separated by dots. The signature
// segment may be empty (alg=none), so the last group allows zero length.
var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*`)

// Find returns the unique JWT candidates found in r, in first-seen order.
func Find(r io.Reader) []string {
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		for _, m := range jwtRe.FindAllString(sc.Text(), -1) {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

// FindString is a convenience wrapper over Find for in-memory text.
func FindString(s string) []string {
	return Find(strings.NewReader(s))
}
