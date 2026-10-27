// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL028(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		wantHits    int
		wantMessage string
	}{
		{
			name: "untracked true without restriction",
			yaml: `build:
  script:
    - make build
  artifacts:
    untracked: true`,
			wantHits: 1,
		},
		{
			name: "untracked true with paths — reported",
			yaml: `build:
  script:
    - make build
  artifacts:
    untracked: true
    paths:
      - dist/`,
			wantHits: 1,
		},
		{
			name: "untracked true with paths and exclude — safe",
			yaml: `build:
  script:
    - make build
  artifacts:
    untracked: true
    paths:
      - dist/
    exclude:
      - "**/__pycache__/**/*"
      - "**/.env"`,
			wantHits: 0,
		},
		{
			name: "untracked true with key exclude — safe",
			yaml: `build:
  script:
    - make build
  artifacts:
    untracked: true
    exclude:
      - "**/*.key"`,
			wantHits: 0,
		},
		{
			name: "untracked true with pem exclude — safe",
			yaml: `build:
  script:
    - make build
  artifacts:
    untracked: true
    exclude:
      - "**/*.pem"`,
			wantHits: 0,
		},
		{
			name: "untracked true with credentials exclude — safe",
			yaml: `build:
  script:
    - make build
  artifacts:
    untracked: true
    exclude:
      - "**/credentials*"`,
			wantHits: 0,
		},
		{
			name: "untracked true with unrelated exclude — reported",
			yaml: `build:
  script:
    - make build
  artifacts:
    untracked: true
    exclude:
      - "**/__pycache__/**/*"`,
			wantHits:    1,
			wantMessage: "does not cover sensitive files",
		},
		{
			name: "untracked true with empty exclude — reported",
			yaml: `build:
  script:
    - make build
  artifacts:
    untracked: true
    exclude: []`,
			wantHits: 1,
		},
		{
			name: "untracked false — safe",
			yaml: `build:
  script:
    - make build
  artifacts:
    untracked: false`,
			wantHits: 0,
		},
		{
			name: "no artifacts block — safe",
			yaml: `build:
  script:
    - make build`,
			wantHits: 0,
		},
		{
			name: "multiple jobs — both flagged when lacking exclude",
			yaml: `build:
  script:
    - make build
  artifacts:
    untracked: true
test:
  script:
    - make test
  artifacts:
    untracked: true
    paths:
      - reports/`,
			wantHits: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL028.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
			if tt.wantMessage != "" && len(findings) == 1 && !strings.Contains(findings[0].Message, tt.wantMessage) {
				t.Errorf("finding message %q does not contain %q", findings[0].Message, tt.wantMessage)
			}
		})
	}
}
