package masker

import "strings"

const EmailPrefixLen = 3

// Email mask email
func Email(v string) string {
	l := len([]rune(v))
	if l == 0 {
		return ""
	}

	items := strings.Split(v, "@")
	if len(items) == 1 { // DON'T mask invalid email
		return v
	}

	addr := items[0]
	domain := items[1]
	return addOverlay(addr, EmailPrefixLen, 0, "*") + "@" + domain
}
