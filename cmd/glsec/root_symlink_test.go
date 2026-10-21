// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runInRepo creates repo/ci/pipeline.yml and outside/secret.yml, points
// repo/.gitlab-ci.yml at target with a symbolic link and runs glsec in repo.
func runInRepo(t *testing.T, target string) (code int, stdout, stderr string) {
	t.Helper()
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	files := map[string]string{
		filepath.Join(repo, "ci", "pipeline.yml"):   childJob,
		filepath.Join(dir, "outside", "secret.yml"): grandJob,
	}
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, target), filepath.Join(repo, ".gitlab-ci.yml")); err != nil {
		t.Skipf("symlinks not available: %v", err)
	}
	t.Chdir(repo)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	var out, errOut bytes.Buffer
	code = run([]string{"--format", "json", "--only", "GL001"}, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRun_RootSymlinkOutsideRejected(t *testing.T) {
	code, stdout, stderr := runInRepo(t, filepath.Join("outside", "secret.yml"))
	if code != 2 {
		t.Errorf("exit code %d, want 2", code)
	}
	if !strings.Contains(stderr, "symbolic link to a file outside its directory") {
		t.Errorf("stderr lacks the symlink error:\n%s", stderr)
	}
	if strings.Contains(stdout+stderr, "python") {
		t.Errorf("output shows content of a file outside the repository:\n%s%s", stdout, stderr)
	}
}

func TestRun_RootSymlinkInsideAllowed(t *testing.T) {
	code, stdout, stderr := runInRepo(t, filepath.Join("repo", "ci", "pipeline.yml"))
	if code != 1 || !strings.Contains(stdout, "node:latest") {
		t.Errorf("exit code %d, want 1 with a GL001 finding; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
}
