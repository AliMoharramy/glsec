// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl024 struct{}

var GL024 = &gl024{}

func (r *gl024) ID() string { return "GL024" }

var (
	// pipefailRe matches a line that enables pipefail.
	pipefailRe = regexp.MustCompile(`\bpipefail\b`)
	// The assignment's quotes are outside the substituted command's context.
	printCommandSubstRe = regexp.MustCompile(`^(?:(?:export|local|readonly|declare)\s+)?[A-Za-z_][A-Za-z0-9_]*="?\$\(`)
)

func (r *gl024) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	inherit := NewInheritance(doc)
	pipefail := nodeMemo[bool]{}
	firstPipe := nodeMemo[int]{} // index of the item line, or -1
	hasPipefail := func(l *yaml.Node) bool {
		return pipefail.get(l, func() bool { return pipefailRe.MatchString(l.Value) })
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		lines := CollectJobScriptLines(job)
		if len(lines) == 0 {
			return
		}
		// Windows runners run PowerShell, which has no pipefail (#615).
		if inherit.RunsOnWindows(job) {
			return
		}

		// Check if pipefail is set anywhere in the job's script, including the
		// before_script/script it inherits through extends: or default: (#615).
		// An inherited after_script runs in a separate shell, so it doesn't count.
		for _, l := range lines {
			if hasPipefail(l) {
				return
			}
		}
		for _, key := range []string{"before_script", "script"} {
			if parser.FindKey(job, key) != nil {
				continue
			}
			if seq := inherit.Key(job, key); isScriptList(seq) {
				for _, l := range seq.Content {
					if l.Kind == yaml.ScalarNode && hasPipefail(l) {
						return
					}
				}
			}
		}

		// Find the first pipeline that needs pipefail. A | inside quotes, as
		// in sed "s|a|b|" or grep "a|b", is part of an argument.
		for _, l := range lines {
			at := firstPipe.get(l, func() int {
				pipelineLine := -1
				for _, cmd := range shellCommands(l.Value) {
					if !cmd.piped {
						pipelineLine = -1
						continue
					}
					if pipelineLine < 0 {
						pipelineLine = cmd.line
					}
					if !isSimplePrintCommand(cmd.text) {
						return pipelineLine
					}
				}
				return -1
			})
			if at < 0 {
				continue
			}
			f := finding.Finding{
				RuleID:   "GL024",
				Severity: finding.Warn,
				Job:      name.Value,
				Message:  "script uses a pipe without set -o pipefail — failures in all but the last command are silently ignored",
				File:     file,
				Line:     parser.ScalarContentLine(l, at),
			}
			if at == 0 {
				f.Col = l.Column
			}
			findings = append(findings, f)
			return // one finding per job
		}
	})

	return findings
}

// isSimplePrintCommand recognises commands that only write an existing value.
func isSimplePrintCommand(text string) bool {
	if at := printCommandSubstRe.FindStringIndex(text); at != nil {
		text = text[at[1]:]
	}
	words := commandWords(text)
	if len(words) == 0 || words[0] != "echo" && words[0] != "printf" {
		return false
	}
	// Keep checking substitutions, compound commands and redirections: they
	// can do more than print. Quoted or escaped syntax is only argument data.
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '\\' && quote != '\'':
			i++
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\'' && quote == 0:
			quote = c
		case c == '"':
			if quote == '"' {
				quote = 0
			} else {
				quote = c
			}
		case c == '`' || c == '$' && strings.HasPrefix(text[i:], "$("):
			return false
		case quote == 0 && strings.ContainsRune("()<>", rune(c)):
			return false
		}
	}
	return true
}
