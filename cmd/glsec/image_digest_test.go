// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRun_RequireImageDigestCache(t *testing.T) {
	files := map[string]string{
		".glsec.yml":     "require_image_digest: true\n",
		".gitlab-ci.yml": "job:\n  image: node:22.1.0\n  script: [make]\n",
	}
	args := []string{"--only", "GL001", "--format", "json"}
	if code, out, stderr := runCLI(t, files, args...); code != 0 || !strings.Contains(out, "GL001") {
		t.Fatalf("initial scan: exit %d, %s, %s", code, out, stderr)
	}
	if err := os.WriteFile(".glsec.yml", []byte("require_image_digest: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if code := run(args, &out, &stderr); code != 0 || strings.Contains(out.String(), "GL001") {
		t.Fatalf("stale policy finding after config change: exit %d, %s, %s", code, &out, &stderr)
	}
}

func TestRun_RequireImageDigest(t *testing.T) {
	const pipeline = "job:\n  image: node:22.1.0\n  services: [redis:7.2.4]\n  script: [make]\n"
	for _, tc := range []struct {
		name, config   string
		args           []string
		code, findings int
	}{
		{"default", "", nil, 0, 0},
		{"disabled", "require_image_digest: false\n", nil, 0, 0},
		{"enabled", "require_image_digest: true\n", nil, 0, 2},
		{"strict", "require_image_digest: true\n", []string{"--strict"}, 1, 2},
		{"rule disabled", "require_image_digest: true\nrules: {GL001: off}\n", nil, 0, 0},
		{"severity override", "require_image_digest: true\nrules: {GL001: error}\n", nil, 1, 2},
		{"untrusted repo config", "require_image_digest: true\n", []string{"--no-repo-config"}, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{".gitlab-ci.yml": pipeline}
			if tc.config != "" {
				files[".glsec.yml"] = tc.config
			}
			args := append([]string{"--no-cache", "--only", "GL001", "--format", "json"}, tc.args...)
			code, out, stderr := runCLI(t, files, args...)
			if code != tc.code || strings.Count(out, `"rule": "GL001"`) != tc.findings {
				t.Fatalf("exit %d, output %s, stderr %s; want exit %d and %d findings", code, out, stderr, tc.code, tc.findings)
			}
			// A subsequent scan with default config must reset the singleton.
			code, out, stderr = runCLI(t, map[string]string{".gitlab-ci.yml": pipeline}, "--no-cache", "--only", "GL001", "--format", "json")
			if code != 0 || strings.Contains(out, "GL001") {
				t.Fatalf("policy leaked into default scan: exit %d, %s, %s", code, out, stderr)
			}
		})
	}
}
