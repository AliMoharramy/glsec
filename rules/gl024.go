// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
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
	type pipedLines struct {
		first, count int
	}
	pipes := nodeMemo[pipedLines]{}
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

		// Count lines with pipelines that need pipefail, retaining the first
		// location. Multiple pipes on the same line count once.
		var first *yaml.Node
		var firstLine, count int
		for _, l := range lines {
			pl := pipes.get(l, func() pipedLines {
				var result pipedLines
				pipelineLine, lastCountedLine := -1, -1
				for _, cmd := range shellCommands(l.Value) {
					if !cmd.piped {
						pipelineLine = -1
						continue
					}
					if pipelineLine < 0 {
						pipelineLine = cmd.line
					}
					if pipelineLine != lastCountedLine && !isSimplePrintCommand(cmd.text) {
						if result.count == 0 {
							result.first = pipelineLine
						}
						result.count++
						lastCountedLine = pipelineLine
					}
				}
				return result
			})
			count += pl.count
			if first == nil && pl.count > 0 {
				first, firstLine = l, pl.first
			}
		}
		if count == 0 {
			return
		}
		countHint := ""
		if count > 1 {
			countHint = fmt.Sprintf(" (%d piped lines in this job, first shown)", count)
		}
		f := finding.Finding{
			RuleID:   "GL024",
			Severity: finding.Warn,
			Job:      name.Value,
			Message:  "script uses a pipe without set -o pipefail" + countHint + " — failures in all but the last command are silently ignored",
			File:     file,
			Line:     parser.ScalarContentLine(first, firstLine),
		}
		if firstLine == 0 {
			f.Col = first.Column
		}
		findings = append(findings, f) // one finding per job
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
