package jwt

import (
	"strconv"
	"strings"
	"time"
)

// timeNow is overridable in tests.
var timeNow = time.Now

// relTime parses a relative offset like "+1h", "-30m", "+7d", "+90s" into a
// unix timestamp relative to now. Returns ok=false if s is not a relative spec.
func relTime(s string) (int64, bool) {
	if len(s) < 2 || (s[0] != '+' && s[0] != '-') {
		return 0, false
	}
	unit := s[len(s)-1]
	var mult int64
	switch unit {
	case 's':
		mult = 1
	case 'm':
		mult = 60
	case 'h':
		mult = 3600
	case 'd':
		mult = 86400
	default:
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSuffix(s, string(unit)), 10, 64)
	if err != nil {
		return 0, false
	}
	return timeNow().Unix() + n*mult, true
}
