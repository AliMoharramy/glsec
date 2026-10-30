// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestInterspersedFlags(t *testing.T) {
	files := map[string]string{
		".gitlab-ci.yml": errorPipeline,
		"second.yml":     errorPipeline,
		"--format":       errorPipeline,
		"--policy.yml":   "no-exit-codes: true\n",
	}
	for _, tc := range []struct {
		name        string
		args        []string
		code        int
		out, stderr string
		json        bool
	}{
		{"value after file", []string{".gitlab-ci.yml", "--format", "json", "--only", "GL001"}, 1, `"rule": "GL001"`, "", true},
		{"boolean after file", []string{".gitlab-ci.yml", "--no-exit-codes"}, 0, "GL001", "", false},
		{"explicit boolean false", []string{".gitlab-ci.yml", "--no-exit-codes=false"}, 1, "GL001", "", false},
		{"equals value", []string{".gitlab-ci.yml", "--format=json"}, 1, `"findings"`, "", true},
		{"single dash flag", []string{".gitlab-ci.yml", "-format", "json"}, 1, `"findings"`, "", true},
		{"multiple files", []string{".gitlab-ci.yml", "--format", "json", "second.yml"}, 1, "second.yml", "", true},
		{"repeated value flags", []string{".gitlab-ci.yml", "--format", "text", "--format", "json"}, 1, `"findings"`, "", true},
		{"repeatable flag", []string{".gitlab-ci.yml", "--only", "GL001", "--only", "GL053", "--format", "json"}, 1, "GL053", "", true},
		{"dash-prefixed value", []string{".gitlab-ci.yml", "--config", "--policy.yml"}, 0, "GL001", "", false},
		{"literal flag filename", []string{"--format", "json", "--", "--format"}, 1, `"file": "--format"`, "", true},
		{"terminator after file", []string{".gitlab-ci.yml", "--format", "json", "--", "--format"}, 1, `"file": "--format"`, "", true},
		{"missing value", []string{".gitlab-ci.yml", "--format"}, 2, "", "flag needs an argument", false},
		{"unknown flag", []string{".gitlab-ci.yml", "--bogus"}, 2, "", "flag provided but not defined", false},
		{"help after file", []string{".gitlab-ci.yml", "--help"}, 0, "", "usage:", false},
		{"explain trailing flag", []string{"explain", "GL001", "--no-color"}, 0, "GL001", "", false},
		{"explain leading flag", []string{"explain", "--no-color", "GL001"}, 0, "GL001", "", false},
		{"explain unknown flag", []string{"explain", "GL001", "--bogus"}, 2, "", "flag provided but not defined", false},
		{"explain extra argument", []string{"explain", "GL001", "GL002"}, 2, "", "usage:", false},
		{"explain terminator", []string{"explain", "--", "--no-color"}, 2, "", "unknown rule", false},
		{"explain help", []string{"explain", "GL001", "--help"}, 0, "", "usage:", false},
		{"list valid flags", []string{"list", "--format", "json", "--owasp", "CICD-SEC-3"}, 0, "GL001", "", true},
		{"list leading flag with argument", []string{"list", "--format", "json", "unexpected"}, 2, "", "usage:", false},
		{"list trailing flag with argument", []string{"list", "unexpected", "--format", "json"}, 2, "", "usage:", false},
		{"list terminator", []string{"list", "--", "--format"}, 2, "", "usage:", false},
		{"inventory trailing value", []string{"inventory", ".gitlab-ci.yml", "--format", "jobs"}, 0, `"jobs"`, "", true},
		{"inventory leading value", []string{"inventory", "--format", "jobs", ".gitlab-ci.yml"}, 0, `"jobs"`, "", true},
		{"inventory literal filename", []string{"inventory", "--format", "jobs", "--", "--format"}, 0, `"jobs"`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, stderr := runCLI(t, files, tc.args...)
			if code != tc.code || !strings.Contains(out, tc.out) || !strings.Contains(stderr, tc.stderr) {
				t.Fatalf("run(%v): exit %d, stdout %s, stderr %s; want exit %d, stdout containing %q, stderr containing %q", tc.args, code, out, stderr, tc.code, tc.out, tc.stderr)
			}
			if tc.json && !json.Valid([]byte(out)) {
				t.Errorf("invalid JSON output: %s", out)
			}
		})
	}
}

func TestParseFlags_RegisteredTypesAndValues(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	count := fs.Int("count", 0, "")
	label := fs.String("label", "", "")
	boolean := fs.Bool("switch", false, "")
	var items []string
	fs.Func("item", "", func(value string) error { items = append(items, value); return nil })
	args := []string{"first", "--count", "-3", "--switch", "second", "--label", "--literal", "--item", "one", "--switch=false", "--item=two", "--", "--switch", "-"}
	original := slices.Clone(args)
	if err := parseFlags(fs, args); err != nil {
		t.Fatal(err)
	}
	if *count != -3 || *label != "--literal" || *boolean || !slices.Equal(items, []string{"one", "two"}) {
		t.Errorf("wrong parsed values: count %d, label %q, switch %v, items %v", *count, *label, *boolean, items)
	}
	if !slices.Equal(fs.Args(), []string{"first", "second", "--switch", "-"}) {
		t.Errorf("positional args = %v", fs.Args())
	}
	if !slices.Equal(args, original) {
		t.Error("parser modified its input arguments")
	}
}

func TestParseFlags_TerminatorAsFlagValue(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	label := fs.String("label", "", "")
	if err := parseFlags(fs, []string{"file", "--label", "--"}); err != nil {
		t.Fatal(err)
	}
	if *label != "--" || !slices.Equal(fs.Args(), []string{"file"}) {
		t.Errorf("label = %q, args = %v", *label, fs.Args())
	}
}
