// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"fmt"
	"strings"
	"unicode"
)

// Sanitize escapes the characters in s that a terminal or a GitLab job log
// would act on rather than print: control characters (escape sequences,
// carriage returns, line breaks), Unicode line separators and bidirectional
// overrides. Job names, paths and source lines come from the scanned file, so
// printed raw they could hide findings or forge glsec output.
func Sanitize(s string) string {
	return sanitize(s, false)
}

// sanitizeSource is Sanitize for a source line, which keeps its tabs.
func sanitizeSource(s string) string {
	return sanitize(s, true)
}

func sanitize(s string, keepTab bool) string {
	if strings.IndexFunc(s, func(r rune) bool { return unsafeRune(r, keepTab) }) < 0 {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case !unsafeRune(r, keepTab):
			b.WriteRune(r)
		case r < 0x80:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

func unsafeRune(r rune, keepTab bool) bool {
	switch {
	case r == '\t':
		return !keepTab
	case unicode.IsControl(r):
		return true
	case r == '\u2028', r == '\u2029':
		return true
	case r >= '\u202a' && r <= '\u202e', r >= '\u2066' && r <= '\u2069', r == '\u200e', r == '\u200f', r == '\u061c':
		return true
	}
	return false
}
