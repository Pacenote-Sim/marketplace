package check_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pacenote-sim/marketplace/internal/check"
	"github.com/pacenote-sim/marketplace/internal/manifest"
	"github.com/pacenote-sim/marketplace/internal/policy"
)

func loadPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Load(filepath.Join("..", "..", "policy"))
	require.NoError(t, err)
	return p
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("testdata", name))
	require.NoError(t, err)
	return dir
}

func companion(name, module, of string, calls []string) (*manifest.Manifest, *manifest.Version) {
	m := &manifest.Manifest{
		Name: name, Kind: manifest.KindCompanion, Title: "T", Summary: "A companion for the tests.",
		Author: "t", Contact: "t@example.com", Repository: "https://github.com/x/y", Module: module,
		Licence: "MIT", Visibility: manifest.Public, Pricing: manifest.Free, Calls: calls, CompanionOf: of,
		Versions: []manifest.Version{{Tag: "v0.1.0", Approved: "2026-09-24", Reviewer: "r", InterfaceVersion: 1, Status: manifest.StatusApproved}},
	}
	return m, &m.Versions[0]
}

func findings(r *check.Report, name string, sev check.Severity) []string {
	var out []string
	for _, f := range r.Findings {
		if f.Check == name && f.Severity == sev {
			out = append(out, f.Detail)
		}
	}
	return out
}

func TestRun_GoodCompanion(t *testing.T) {
	t.Parallel()
	m, v := companion("client-demo", "example.test/companion-ok", "demo", []string{})
	r, err := check.Run(context.Background(), check.Options{
		Manifest: m, Version: v, Dir: fixture(t, "companion-ok"), Policy: loadPolicy(t), Runner: check.Exec{},
	})
	require.NoError(t, err)
	for _, f := range r.Findings {
		t.Log(f)
	}
	assert.False(t, r.Failed(), "a well-behaved companion passes every check")
	assert.NotEmpty(t, findings(r, "licence", check.Info))
	assert.NotEmpty(t, findings(r, "manifest", check.Info))
	assert.NotEmpty(t, findings(r, "imports", check.Info))
	assert.NotEmpty(t, findings(r, "hosts", check.Info), "www.pacenote.tech is a known host")
	assert.Len(t, findings(r, "build", check.Info), 3, "one per client platform")
	assert.NotEmpty(t, findings(r, "vet", check.Info))
	assert.NotEmpty(t, findings(r, "tidy", check.Info))
}

func TestRun_BadCompanion(t *testing.T) {
	t.Parallel()
	m, v := companion("client-demo", "example.test/companion-bad", "demo", []string{"api.declared.example"})
	r, err := check.Run(context.Background(), check.Options{
		Manifest: m, Version: v, Dir: fixture(t, "companion-bad"), Policy: loadPolicy(t), Runner: check.Exec{},
	})
	require.NoError(t, err)
	all := strings.Join(details(r), "\n")
	assert.True(t, r.Failed())
	assert.Contains(t, all, "no LICENSE file")
	assert.Contains(t, all, `says name "other"`, "the companion is named after another server plugin")
	assert.Contains(t, all, "interface version 2, the marketplace says 1")
	assert.Contains(t, all, "imports os:", "os is not in the companion policy")
	assert.Contains(t, all, "imports os/exec:")
	assert.Contains(t, all, "http.Get is not something")
	assert.Contains(t, all, "os.ReadFile is not something")
	assert.Contains(t, all, "exec.Command is not something")
	assert.Contains(t, all, "evil.example.net is not in calls")
	assert.Contains(t, all, "api.declared.example is declared in calls but no string literal names it")
	assert.NotContains(t, all, "declared or explained", "hosts summary is not written when a host is undeclared")
}

func TestRun_ImportsAllowAndNotHosts(t *testing.T) {
	t.Parallel()
	m, v := companion("client-demo", "example.test/companion-bad", "other", []string{})
	m.ImportsAllow = []manifest.Reasoned{{Value: "os", Reason: "test"}, {Value: "os/exec", Reason: "test"}}
	m.NotHosts = []string{"evil.example.net"}
	v.InterfaceVersion = 2
	r, err := check.Run(context.Background(), check.Options{
		Manifest: m, Version: v, Dir: fixture(t, "companion-bad"), Policy: loadPolicy(t), Runner: check.Exec{},
	})
	require.NoError(t, err)
	all := strings.Join(details(r), "\n")
	assert.NotContains(t, all, "imports os:", "imports_allow lifts the import rule")
	assert.NotContains(t, all, "os.ReadFile", "and the symbol rule for that package")
	assert.Contains(t, all, "http.Get is not something", "but not for net/http, which was not allowed")
	assert.NotContains(t, all, "evil.example.net is not in calls", "not_hosts explains the literal")
	assert.Contains(t, all, "interface version 2 is not one the current client accepts")
	assert.Len(t, findings(r, "imports", check.Warn), 2, "each imports_allow is shown to the reviewer")
}

func TestRun_GoodServer(t *testing.T) {
	t.Parallel()
	m := &manifest.Manifest{
		Name: "demo-server", Kind: manifest.KindServer, Title: "T", Summary: "A server plugin for the tests.",
		Author: "t", Contact: "t@example.com", Repository: "https://github.com/x/y", Module: "example.test/server-ok",
		Licence: "MIT", Visibility: manifest.Public, Pricing: manifest.Free, Calls: []string{"api.example-vendor.com"},
		Versions: []manifest.Version{{Tag: "v0.1.0", Approved: "2026-09-24", Reviewer: "r", InterfaceVersion: 3, Status: manifest.StatusApproved}},
	}
	r, err := check.Run(context.Background(), check.Options{
		Manifest: m, Version: &m.Versions[0], Dir: fixture(t, "server-ok"), Policy: loadPolicy(t), Runner: check.Exec{},
	})
	require.NoError(t, err)
	for _, f := range r.Findings {
		t.Log(f)
	}
	assert.False(t, r.Failed())
	assert.Len(t, findings(r, "build", check.Info), 5, "one per server platform")
	assert.NotEmpty(t, findings(r, "reproducible", check.Info))
	assert.Empty(t, findings(r, "imports", check.Info), "a server plugin has no import policy")

	m.Calls = []string{}
	r, err = check.Run(context.Background(), check.Options{
		Manifest: m, Version: &m.Versions[0], Dir: fixture(t, "server-ok"), Policy: loadPolicy(t), Runner: check.Exec{},
	})
	require.NoError(t, err)
	all := strings.Join(details(r), "\n")
	assert.Contains(t, all, "declares calls [api.example-vendor.com], the marketplace []")
	assert.Contains(t, all, "api.example-vendor.com is not in calls")
}

func TestRun_Options(t *testing.T) {
	t.Parallel()
	_, err := check.Run(context.Background(), check.Options{})
	require.Error(t, err)
}

func TestFetch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir, err := check.Fetch(ctx, fakeRunner{out: `{"Path":"x","Version":"v1","Dir":"/tmp/x@v1"}`}, "x", "v1")
	require.NoError(t, err)
	assert.Equal(t, "/tmp/x@v1", dir)

	_, err = check.Fetch(ctx, fakeRunner{out: `{"Error":"no such tag"}`, err: errors.New("exit 1")}, "x", "v9")
	require.ErrorContains(t, err, "no such tag")

	_, err = check.Fetch(ctx, fakeRunner{out: `garbage`, err: errors.New("exit 1")}, "x", "v9")
	require.ErrorContains(t, err, "exit 1")

	_, err = check.Fetch(ctx, fakeRunner{out: `garbage`}, "x", "v9")
	require.ErrorContains(t, err, "unexpected output")

	_, err = check.Fetch(ctx, fakeRunner{out: `{}`}, "x", "v9")
	require.ErrorContains(t, err, "no directory")
}

func TestExec(t *testing.T) {
	t.Parallel()
	out, err := check.Exec{}.Run(context.Background(), ".", nil, "go", "env", "GOWORK")
	require.NoError(t, err)
	assert.Equal(t, "off", strings.TrimSpace(string(out)), "checks never run inside a workspace")
	_, err = check.Exec{}.Run(context.Background(), ".", nil, "go", "no-such-command")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown command", "standard error is in the error")

	out, err = check.Exec{}.Run(context.Background(), ".", nil, "sh", "-c", "echo noise >&2; echo '{\"ok\":true}'")
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true}`, string(out), "standard error never mixes into what a caller parses")
}

func TestRun_ListFails(t *testing.T) {
	t.Parallel()
	m, v := companion("client-demo", "example.test/companion-ok", "demo", []string{})
	_, err := check.Run(context.Background(), check.Options{
		Manifest: m, Version: v, Dir: fixture(t, "companion-ok"), Policy: loadPolicy(t),
		Runner: fakeRunner{err: errors.New("boom")},
	})
	require.ErrorContains(t, err, "list packages")
}

func TestFinding_String(t *testing.T) {
	t.Parallel()
	f := check.Finding{Check: "hosts", Severity: check.Fail, Detail: "x"}
	assert.Equal(t, "fail hosts        x", f.String())
}

type fakeRunner struct {
	out string
	err error
}

func (f fakeRunner) Run(context.Context, string, []string, string, ...string) ([]byte, error) {
	return []byte(f.out), f.err
}

func details(r *check.Report) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.Detail)
	}
	return out
}
