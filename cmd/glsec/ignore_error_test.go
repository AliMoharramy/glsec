// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/suppress"
)

// TestRun_UnreadableIgnoreFails: a .glsec-ignore that exists but cannot be
// read stops the scan with exit 2 and a message on stderr, like an unreadable
// .glsec.yml, instead of silently scanning without the suppressions.
func TestRun_UnreadableIgnoreFails(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("chmod 000 does not stop a Windows or root reader")
	}
	dir := t.TempDir()
	files := map[string]string{
		"ci.yml":        plainYAML,
		".glsec-ignore": "ci.yml:2 GL001\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(dir, suppress.IgnoreFile), 0); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("FORCE_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")

	var out, errOut bytes.Buffer
	code := run([]string{"--no-cache", "ci.yml"}, &out, &errOut)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (stderr: %s)", code, errOut.String())
	}
	if msg := errOut.String(); !strings.Contains(msg, "error: "+suppress.IgnoreFile+": ") {
		t.Fatalf("stderr = %q, want it to name the unreadable ignore file", msg)
	}
}
