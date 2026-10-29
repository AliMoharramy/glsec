// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func TestGL001_RequireImageDigest(t *testing.T) {
	for _, tc := range []struct {
		name, ref string
		enabled   bool
		severity  finding.Severity
	}{
		{"default version", "node:22.1.0", false, ""},
		{"required version", "node:22.1.0", true, finding.Warn},
		{"version variant", "docker:27.3.1-dind", true, finding.Warn},
		{"registry port", "registry.example.com:5000/team/node:22.1.0", true, finding.Warn},
		{"digest", "node@sha256:abc123", true, ""},
		{"tag and digest", "node:22.1.0@sha256:abc123", true, ""},
		{"unknown variable", "$IMAGE", true, ""},
		{"variable tag", "node:$TAG", true, ""},
		{"variable registry", "$REGISTRY/node:22.1.0", true, ""},
		{"variable digest", "node@${DIGEST}", true, ""},
		{"partial variable", "ci-env$TAG_SUFFIX", true, ""},
		{"macOS runner", "macos-14-xcode-15", true, ""},
		{"moving tag", "node:latest", true, finding.Error},
		{"versionless tag", "node:alpine", true, finding.Warn},
		{"missing tag", "node", true, finding.Error},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &gl001{}
			r.SetRequireImageDigest(tc.enabled)
			doc, err := parser.Parse([]byte("job:\n  image: '"+tc.ref+"'\n  script: [make]\n"), "test.yml")
			if err != nil {
				t.Fatal(err)
			}
			fs := r.Check(doc.Root, "test.yml")
			if tc.severity == "" {
				if len(fs) != 0 {
					t.Fatalf("unexpected findings: %v", fs)
				}
				return
			}
			if len(fs) != 1 {
				t.Fatalf("got %d findings, want 1", len(fs))
			}
			f := fs[0]
			if f.RuleID != "GL001" || f.Severity != tc.severity || f.File != "test.yml" || f.Job != "job" || f.Line != 2 || f.Col != 10 {
				t.Errorf("wrong finding: %+v", f)
			}
			if tc.enabled && tc.ref != "node" && (!strings.Contains(f.Message, "can be moved") || !strings.Contains(f.Message, "@sha256:")) {
				t.Errorf("missing digest advice: %s", f.Message)
			}
		})
	}
}

func TestGL001_DigestPolicyAllImageLocations(t *testing.T) {
	r := &gl001{}
	r.SetRequireImageDigest(true)
	doc, err := parser.Parse([]byte("image: node:22.1.0\nservices: [redis:7.2.4]\ndefault:\n  image: {name: node:22.1.0}\n  services: [{name: redis:7.2.4}]\njob:\n  image: {name: node:22.1.0}\n  services: [{name: redis:7.2.4}]\n  script: [make]\n"), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	fs := r.Check(doc.Root, "test.yml")
	if len(fs) != 6 {
		t.Fatalf("got %d findings, want all 6 image/service references", len(fs))
	}
	for i, f := range fs {
		if f.Severity != finding.Warn || (i < 4 && f.Job != "") || (i >= 4 && f.Job != "job") {
			t.Errorf("wrong attribution: %+v", f)
		}
	}
}

func TestGL001_DigestPolicyKeepsVariableResolution(t *testing.T) {
	r := &gl001{}
	r.SetRequireImageDigest(true)
	doc, err := parser.Parse([]byte("variables: {IMAGE: 'node:22.1.0'}\njob:\n  image: $IMAGE\n  script: [make]\n"), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	if fs := r.Check(doc.Root, "test.yml"); len(fs) != 0 {
		t.Fatalf("dynamic reference gained a digest warning: %v", fs)
	}
	doc, err = parser.Parse([]byte("variables: {IMAGE: 'node:latest'}\njob:\n  image: $IMAGE\n  script: [make]\n"), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	if fs := r.Check(doc.Root, "test.yml"); len(fs) != 1 || fs[0].Severity != finding.Error {
		t.Fatalf("existing moving-tag finding lost: %v", fs)
	}
}
