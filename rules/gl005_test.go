// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings005(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL005.Check(doc.Root, "test.yml")
}

func TestGL005_EnvFile(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - .env.production
    expire_in: 1 week
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for .env file, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL005_PemFile(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - deploy-key.pem
    expire_in: 1 week
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for .pem file, got %d", len(f))
	}
}

func TestGL005_NoExpiry(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - dist/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for missing expire_in, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity for missing expiry")
	}
}

func TestGL005_SensitiveAndNoExpiry(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - .env.production
      - dist/
`)
	// .env finding (Error) + no expire_in (Warn)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
}

func TestGL005_SafeArtifactWithExpiry(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - dist/
      - coverage.xml
    expire_in: 7 days
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for safe artifact with expiry, got %d", len(f))
	}
}

func TestGL005_KeyFile(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - secrets/api.key
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for .key file, got %d", len(f))
	}
}

func TestGL005_SecretInPath(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - output/db_password.txt
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for password in filename, got %d", len(f))
	}
}

func TestGL005_TerraformState(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - terraform.tfstate
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for tfstate, got %d", len(f))
	}
}

func TestGL005_DefaultBlockSensitivePath(t *testing.T) {
	f := findings005(t, `
default:
  artifacts:
    paths:
      - .env.production
    expire_in: 1 week

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for sensitive path in default: artifacts:, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL005_DefaultBlockNoExpiry(t *testing.T) {
	f := findings005(t, `
default:
  artifacts:
    paths:
      - dist/

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for missing expire_in in default: artifacts:, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
}

func TestGL005_AbsolutePath(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - /etc/passwd
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for absolute path, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL005_PathTraversal(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - ../../etc/shadow
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for path traversal, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL005_UserControlledVarNoFinding(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - dist/$CI_COMMIT_REF_NAME
    expire_in: 1 day
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for common branch-based artifact path, got %d", len(f))
	}
}

func TestGL005_ExcludePath(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - dist/
    exclude:
      - ../secrets.env
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for traversal in exclude, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL005_AbsolutePathWithVar(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - /tmp/$CI_COMMIT_REF_NAME
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (absolute path only), got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL005_NoArtifacts(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
`)
	if len(f) != 0 {
		t.Errorf("expected no findings when no artifacts block, got %d", len(f))
	}
}

func TestGL005_LineNumbers(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - .env.production
    expire_in: 1 week
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

func TestGL005_BroadArtifactPaths(t *testing.T) {
	for _, tc := range []struct {
		path string
		risk string
	}{
		{".", "working directory"},
		{"./", "working directory"},
		{"*", "working directory"},
		{"*/", "working directory"},
		{"**", "working directory"},
		{"**/", "working directory"},
		{"$CI_PROJECT_DIR", "working directory"},
		{"$CI_PROJECT_DIR/", "working directory"},
		{"${CI_PROJECT_DIR}", "working directory"},
		{"${CI_PROJECT_DIR}/", "working directory"},
		{".git", ".git"},
		{".git/", ".git"},
		{".git/config", ".git"},
		{"./.git/", ".git"},
		{"foo/.git/**", ".git"},
		{"**/.git/**", ".git"},
		{"foo/.git/.git/config", ".git"},
		{"dist/", ""},
		{"dist/*", ""},
		{"dist/**", ""},
		{"$CI_PROJECT_DIR/dist/", ""},
		{"${CI_PROJECT_DIR}/dist/", ""},
		{"$CI_PROJECT_DIRECTORY", ""},
		{".github/", ""},
		{".gitlab/", ""},
		{".gitignore", ""},
		{".gitmodules", ""},
		{"foo/.github/", ""},
		{"foo/.gitlab/", ""},
		{"foo/.gitignore", ""},
		{"foo/.git-backup/", ""},
	} {
		t.Run(tc.path, func(t *testing.T) {
			f := findings005(t, fmt.Sprintf(`build:
  script: [make]
  artifacts:
    paths:
      - %q
    expire_in: 1 day
`, tc.path))
			if tc.risk == "" {
				if len(f) != 0 {
					t.Fatalf("expected no findings for a narrow or unrelated path, got %v", f)
				}
				return
			}
			if len(f) != 1 {
				t.Fatalf("expected one finding per offending path, got %v", f)
			}
			if f[0].RuleID != "GL005" || f[0].Severity != finding.Error || f[0].Job != "build" {
				t.Errorf("expected a GL005 error attributed to build, got %+v", f[0])
			}
			if f[0].File != "test.yml" || f[0].Line != 5 || f[0].Col != 9 {
				t.Errorf("expected the artifact path's source location, got %+v", f[0])
			}
			if !strings.Contains(f[0].Message, tc.risk) {
				t.Errorf("expected message to explain %q exposure, got %q", tc.risk, f[0].Message)
			}
		})
	}
}

func TestGL005_UntrackedArtifacts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		artifacts string
		want      int
	}{
		{"all untracked files", "    untracked: true", 1},
		{"narrow paths do not restrict untracked files", "    untracked: true\n    paths: [dist/]", 1},
		{"exclusions do not suppress the finding", "    untracked: true\n    exclude: ['**/*.txt']", 1},
		{"untracked false", "    untracked: false", 0},
		{"untracked absent", "    paths: [dist/]", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings005(t, fmt.Sprintf("build:\n  script: [make]\n  artifacts:\n%s\n    expire_in: 1 day\n", tc.artifacts))
			if len(f) != tc.want {
				t.Fatalf("expected %d findings, got %v", tc.want, f)
			}
			if tc.want == 0 {
				return
			}
			if f[0].RuleID != "GL005" || f[0].Severity != finding.Error || f[0].Job != "build" {
				t.Errorf("expected a GL005 error attributed to build, got %+v", f[0])
			}
			if f[0].File != "test.yml" || f[0].Line != 4 || f[0].Col != 16 {
				t.Errorf("expected the untracked value's source location, got %+v", f[0])
			}
			if !strings.Contains(f[0].Message, "untracked files") {
				t.Errorf("expected message to explain what is uploaded, got %q", f[0].Message)
			}
		})
	}
}

func TestGL005_BroadArtifactExclusionsNoFinding(t *testing.T) {
	f := findings005(t, `build:
  script: [make]
  artifacts:
    paths: [dist/]
    exclude: ['.', './', '*', '**', '$CI_PROJECT_DIR', '${CI_PROJECT_DIR}/', '.git/', 'foo/.git/**']
    expire_in: 1 day
`)
	if len(f) != 0 {
		t.Fatalf("excluding broad paths or .git must not be treated as uploading them, got %v", f)
	}
}

func TestGL005_BroadArtifactsKeepExpiryFinding(t *testing.T) {
	f := findings005(t, `build:
  script: [make]
  artifacts:
    paths:
      - ./
      - .git/
    untracked: true
test:
  script: [make test]
  artifacts:
    paths: [coverage.xml]
    expire_in: 1 day
`)
	if len(f) != 4 {
		t.Fatalf("expected two path errors, an untracked error and the existing expiry warning, got %v", f)
	}
	for i, wantLine := range []int{5, 6, 7} {
		if f[i].Severity != finding.Error || f[i].Line != wantLine || f[i].Job != "build" {
			t.Errorf("expected an error on build's line %d, got %+v", wantLine, f[i])
		}
	}
	if f[3].Severity != finding.Warn || f[3].Job != "build" || !strings.Contains(f[3].Message, "expire_in") {
		t.Errorf("expected the existing expiry warning for build, got %+v", f[3])
	}
}

func TestGL005_BroadArtifactsInDefaultsAndTemplates(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		job  string
	}{
		{"default", `default:
  artifacts:
    paths: ['./']
    untracked: true
    expire_in: 1 day
build:
  script: [make]
test:
  script: [make test]
`, ""},
		{"template", `.build:
  artifacts:
    paths: ['.git/']
    untracked: true
    expire_in: 1 day
build:
  extends: .build
  script: [make]
test:
  extends: .build
  script: [make test]
`, ".build"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings005(t, tc.src)
			if len(f) != 2 {
				t.Fatalf("expected one path and one untracked finding where written, got %v", f)
			}
			for i, wantLine := range []int{3, 4} {
				if f[i].Severity != finding.Error || f[i].Line != wantLine || f[i].Job != tc.job {
					t.Errorf("expected error at line %d attributed to %q, got %+v", wantLine, tc.job, f[i])
				}
			}
		})
	}
}

func TestGL005_ExistingPathFindingsUnchanged(t *testing.T) {
	for _, tc := range []struct {
		path    string
		message string
	}{
		{"/tmp/.git", `artifact path "/tmp/.git" is an absolute path — references the host filesystem directly and can exfiltrate arbitrary files on shell executors`},
		{"../.git", `artifact path "../.git" contains path traversal — can escape the project directory on shell executors`},
		{".git/credentials", `artifact path ".git/credentials" matches sensitive file pattern "*credential*" — exclude secrets from artifacts`},
	} {
		t.Run(tc.path, func(t *testing.T) {
			f := findings005(t, fmt.Sprintf("build:\n  script: [make]\n  artifacts:\n    paths: [%q]\n    expire_in: 1 day\n", tc.path))
			if len(f) != 1 || f[0].Severity != finding.Error || f[0].Message != tc.message {
				t.Errorf("expected the existing single path finding %q, got %v", tc.message, f)
			}
		})
	}
}
