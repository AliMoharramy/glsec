// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/baseline"
	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/rules"
)

type findingIdentity struct {
	jsonFinding
	CodeQualityFingerprint string    `json:"code_quality_fingerprint"`
	CodeQualityPath        string    `json:"code_quality_path"`
	SARIFRule              string    `json:"sarif_rule"`
	SARIFURI               string    `json:"sarif_uri"`
	SARIFBase              string    `json:"sarif_base"`
	SASTID                 string    `json:"sast_id"`
	SASTFile               string    `json:"sast_file"`
	SASTIdentifier         string    `json:"sast_identifier"`
	SASTIdentifierType     string    `json:"sast_identifier_type"`
	JSONBaselineKey        [3]string `json:"json_baseline_key"`
	IgnoreBaselineKey      [2]string `json:"ignore_baseline_key"`
}

type identitySnapshot struct {
	Findings []findingIdentity `json:"findings"`
}

func identityFindings(t *testing.T, absolute bool) []finding.Finding {
	t.Helper()
	var findings []finding.Finding
	for _, input := range []struct{ file, source string }{
		{".gitlab-ci.yml", "image: node:latest\nbuild:\n  image: alpine\n  script: [make]\n"},
		{"ci/nested/pipeline.yml", "lint:\n  script:\n    - curl -fsSL https://example.com/data | tee data\n"},
	} {
		file := input.file
		if absolute {
			var err error
			file, err = filepath.Abs(file)
			if err != nil {
				t.Fatal(err)
			}
		}
		doc, err := parser.Parse([]byte(input.source), file)
		if err != nil {
			t.Fatal(err)
		}
		findings = append(findings, rules.GL001.Check(doc.Root, file)...)
		findings = append(findings, rules.GL024.Check(doc.Root, file)...)
		if input.file == ".gitlab-ci.yml" {
			findings = append(findings, rules.GL053.Check(doc.Root, file)...)
		}
	}
	return findings
}

func snapshotIdentities(t *testing.T, findings []finding.Finding) identitySnapshot {
	t.Helper()
	var reports struct {
		JSON        jsonOutput
		CodeQuality []codeClimateIssue
		SARIF       sarifLog
		SAST        gitlabSASTReport
	}
	for _, report := range []struct {
		format Format
		into   any
	}{
		{FormatJSON, &reports.JSON}, {FormatCodeClimate, &reports.CodeQuality},
		{FormatSARIF, &reports.SARIF}, {FormatGitLabSAST, &reports.SAST},
	} {
		var buf bytes.Buffer
		if err := Write(&buf, report.format, findings, 2, false, false); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(buf.Bytes(), report.into); err != nil {
			t.Fatal(err)
		}
	}
	if len(reports.JSON.Findings) != len(findings) || len(reports.CodeQuality) != len(findings) || len(reports.SARIF.Runs[0].Results) != len(findings) || len(reports.SAST.Vulnerabilities) != len(findings) {
		t.Fatal("finding identities changed: a report dropped findings; review compatibility and add an upgrade note")
	}
	var snapshot identitySnapshot
	for i, f := range reports.JSON.Findings {
		sarif := reports.SARIF.Runs[0].Results[i]
		location := sarif.Locations[0].PhysicalLocation.ArtifactLocation
		sast := reports.SAST.Vulnerabilities[i]
		snapshot.Findings = append(snapshot.Findings, findingIdentity{
			jsonFinding:            f,
			CodeQualityFingerprint: reports.CodeQuality[i].Fingerprint,
			CodeQualityPath:        reports.CodeQuality[i].Location.Path,
			SARIFRule:              sarif.RuleID, SARIFURI: location.URI, SARIFBase: location.URIBaseID,
			SASTID: sast.ID, SASTFile: sast.Location.File, SASTIdentifier: sast.Identifiers[0].Value,
			SASTIdentifierType: sast.Identifiers[0].Type,
			JSONBaselineKey:    [3]string{f.Rule, f.File, f.Message},
			IgnoreBaselineKey:  [2]string{f.Rule, f.File},
		})
	}
	sort.Slice(snapshot.Findings, func(i, j int) bool {
		a, b := snapshot.Findings[i], snapshot.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Rule < b.Rule
	})
	return snapshot
}

func TestFindingIdentities(t *testing.T) {
	golden, err := filepath.Abs("testdata/finding-identities.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	for _, absolute := range []bool{false, true} {
		snapshot := snapshotIdentities(t, identityFindings(t, absolute))
		got, err := json.MarshalIndent(snapshot, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, '\n')
		if *updateGolden && !absolute {
			if err := os.WriteFile(golden, got, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(golden) //nolint:gosec // repository-owned golden snapshot
		if err != nil {
			t.Fatalf("%v; create the identity snapshot with go test ./internal/output -run '^TestFindingIdentities$' -update", err)
		}
		if !bytes.Equal(got, bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))) {
			t.Fatalf("finding identities changed (absolute=%v): review testdata/finding-identities.golden.json and add an upgrade note for affected consumers; update intended changes with go test ./internal/output -run '^TestFindingIdentities$' -update\ngot:\n%s\nwant:\n%s", absolute, got, want)
		}
		var saved identitySnapshot
		if err := json.Unmarshal(want, &saved); err != nil {
			t.Fatal(err)
		}
		checkSavedBaselines(t, golden, saved, absolute)
	}
}

func checkSavedBaselines(t *testing.T, golden string, saved identitySnapshot, absolute bool) {
	t.Helper()
	var ignore strings.Builder
	for _, f := range saved.Findings {
		fmt.Fprintf(&ignore, "%s:%d %s\n", f.IgnoreBaselineKey[1], f.Line, f.IgnoreBaselineKey[0])
	}
	ignoreFile := filepath.Join(t.TempDir(), ".glsec-ignore")
	if err := os.WriteFile(ignoreFile, []byte(ignore.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, f := range saved.Findings {
		current := finding.Finding{RuleID: f.JSONBaselineKey[0], File: f.JSONBaselineKey[1], Message: f.JSONBaselineKey[2], Line: f.Line, Job: f.Job}
		for _, tc := range []struct {
			name               string
			change             func(*finding.Finding)
			jsonNew, ignoreNew bool
		}{
			{"line", func(f *finding.Finding) { f.Line += 20 }, false, false},
			{"job", func(f *finding.Finding) { f.Job += "-renamed" }, false, false},
			{"message", func(f *finding.Finding) { f.Message += " changed" }, true, false},
			{"rule", func(f *finding.Finding) { f.RuleID = "GL999" }, true, true},
			{"file", func(f *finding.Finding) { f.File = "different.yml" }, true, true},
		} {
			changed := current
			tc.change(&changed)
			for _, input := range []struct {
				file    string
				wantNew bool
			}{{golden, tc.jsonNew}, {ignoreFile, tc.ignoreNew}} {
				candidate := changed
				if absolute && input.file == golden {
					var err error
					candidate.File, err = filepath.Abs(candidate.File)
					if err != nil {
						t.Fatal(err)
					}
				}
				b, err := baseline.Load(input.file)
				if err != nil {
					t.Fatal(err)
				}
				if got := b.IsNew(candidate); got != input.wantNew {
					t.Errorf("%s %s changed %s: IsNew = %v, want %v; baseline identity changed, review compatibility and add an upgrade note", f.Rule, f.File, tc.name, got, input.wantNew)
				}
			}
		}
	}
}
