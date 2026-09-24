package check_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pacenote-sim/marketplace/internal/check"
	"github.com/pacenote-sim/marketplace/internal/manifest"
)

// writeModule lays out a module in a temp dir from a map of file contents.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	}
	return dir
}

// listJSON is what go list -deps -json would print for the packages given.
func listJSON(pkgs ...map[string]any) string {
	var b strings.Builder
	for _, p := range pkgs {
		j, _ := json.Marshal(p)
		b.Write(j)
		b.WriteString("\n")
	}
	return b.String()
}

func modulePkg(dir, module string, imports []string, files ...string) map[string]any {
	return map[string]any{
		"ImportPath": module, "Name": "p", "Dir": dir, "Module": map[string]string{"Path": module},
		"Imports": imports, "GoFiles": files,
	}
}

func stdPkg(path string) map[string]any {
	return map[string]any{"ImportPath": path, "Name": filepath.Base(path), "Standard": true}
}

func depPkg(path, module string) map[string]any {
	return map[string]any{"ImportPath": path, "Name": filepath.Base(path), "Module": map[string]string{"Path": module}}
}

type exitErr int

func (e exitErr) Error() string { return fmt.Sprintf("exit status %d", int(e)) }
func (e exitErr) ExitCode() int { return int(e) }

// script answers each go subcommand from a table, and can write the file a
// build was asked for so the reproducibility check has something to hash.
type script struct {
	list     string
	fail     map[string]error // subcommand -> error
	buildOut func(n int) string
	builds   int
}

func (s *script) Run(_ context.Context, _ string, _ []string, name string, args ...string) ([]byte, error) {
	key := name
	if name == "go" && len(args) > 0 {
		key = args[0]
		if key == "mod" && len(args) > 1 {
			key = "mod " + args[1]
		}
	}
	if err, ok := s.fail[key]; ok {
		// Like Exec, the error carries the command's output.
		return nil, fmt.Errorf("%w\nsomething went wrong\nline two\nline three\nline four\nline five\nline six\nline seven", err)
	}
	switch key {
	case "list":
		return []byte(s.list), nil
	case "build":
		for i, a := range args {
			if a == "-o" && i+1 < len(args) && s.buildOut != nil {
				s.builds++
				_ = os.WriteFile(args[i+1], []byte(s.buildOut(s.builds)), 0o600)
			}
		}
	}
	return nil, nil
}

func minimalCompanion(t *testing.T, extra map[string]string) (dir string, m *manifest.Manifest, v *manifest.Version) {
	t.Helper()
	files := map[string]string{
		"go.mod":             "module example.test/min\n\ngo 1.26\n",
		"LICENSE":            "x",
		"client-plugin.json": `{"name":"demo","kind":"companion","interface_version":1,"server_plugin":"demo"}`,
		"plugin.go":          "package min\n\nconst Docs = \"https://www.pacenote.tech/docs/\"\n",
	}
	for k, val := range extra {
		files[k] = val
	}
	dir = writeModule(t, files)
	m, v = companion("client-demo", "example.test/min", "demo", []string{})
	return dir, m, v
}

func TestFake_BuildVetTidyVulnFail(t *testing.T) {
	t.Parallel()
	dir, m, v := minimalCompanion(t, nil)
	s := &script{
		list: listJSON(modulePkg(dir, "example.test/min", nil, "plugin.go")),
		fail: map[string]error{"build": errors.New("exit 1"), "vet": errors.New("exit 1"), "mod tidy": errors.New("exit 1"), "govulncheck": exitErr(3)},
	}
	r, err := check.Run(context.Background(), check.Options{Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t), Runner: s, Vuln: true})
	require.NoError(t, err)
	assert.Len(t, findings(r, "build", check.Fail), 3)
	assert.Contains(t, findings(r, "build", check.Fail)[0], "…", "long output is cut to a few lines")
	assert.NotEmpty(t, findings(r, "vet", check.Fail))
	assert.NotEmpty(t, findings(r, "tidy", check.Fail))
	assert.NotEmpty(t, findings(r, "vuln", check.Fail), "govulncheck exit 3 is a reached vulnerability")
	assert.NotEmpty(t, findings(r, "hosts", check.Info))
}

func TestFake_VulnWarnAndOK(t *testing.T) {
	t.Parallel()
	dir, m, v := minimalCompanion(t, nil)
	list := listJSON(modulePkg(dir, "example.test/min", nil, "plugin.go"))
	r, err := check.Run(context.Background(), check.Options{
		Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t), Vuln: true,
		Runner: &script{list: list, fail: map[string]error{"govulncheck": errors.New("not installed")}},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, findings(r, "vuln", check.Warn))

	r, err = check.Run(context.Background(), check.Options{
		Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t), Vuln: true,
		Runner: &script{list: list},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, findings(r, "vuln", check.Info))
}

func TestFake_ImportsBranches(t *testing.T) {
	t.Parallel()
	dir, m, v := minimalCompanion(t, nil)
	m.Dependencies = []manifest.Reasoned{{Value: "github.com/x/listed", Reason: "test"}}
	list := listJSON(
		modulePkg(dir, "example.test/min", []string{"fmt", "github.com/pacenote-sim/clientplugin", "github.com/x/listed/sub", "github.com/y/unlisted", "example.test/min/internal", "vanished"}, "plugin.go"),
		modulePkg(filepath.Join(dir, "internal"), "example.test/min", nil),
		stdPkg("fmt"),
		depPkg("github.com/pacenote-sim/clientplugin", "github.com/pacenote-sim/clientplugin"),
		depPkg("github.com/x/listed/sub", "github.com/x/listed"),
		depPkg("github.com/y/unlisted", "github.com/y/unlisted"),
	)
	r, err := check.Run(context.Background(), check.Options{Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t), Runner: &script{list: list}})
	require.NoError(t, err)
	fails := strings.Join(findings(r, "imports", check.Fail), "\n")
	assert.Contains(t, fails, "vanished, which go list did not describe")
	assert.Contains(t, fails, "github.com/y/unlisted: not listed in dependencies")
	assert.NotContains(t, fails, "clientplugin", "a contract is always allowed")
	assert.NotContains(t, fails, "x/listed", "a listed dependency is allowed")
	assert.NotContains(t, fails, "fmt", "fmt is in the companion policy")
}

func TestFake_DotAndBlankImports(t *testing.T) {
	t.Parallel()
	dir, m, v := minimalCompanion(t, map[string]string{
		"plugin.go": "package min\n\nimport (\n\t. \"net/http\"\n\t_ \"os/exec\"\n)\n\nconst M = MethodGet\n",
	})
	m.ImportsAllow = []manifest.Reasoned{{Value: "os/exec", Reason: "test"}}
	list := listJSON(modulePkg(dir, "example.test/min", []string{"net/http", "os/exec"}, "plugin.go"), stdPkg("net/http"), stdPkg("os/exec"))
	r, err := check.Run(context.Background(), check.Options{Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t), Runner: &script{list: list}})
	require.NoError(t, err)
	syms := strings.Join(findings(r, "symbols", check.Fail), "\n")
	assert.Contains(t, syms, "dot-import of net/http")
}

func TestFake_ParseError(t *testing.T) {
	t.Parallel()
	dir, m, v := minimalCompanion(t, map[string]string{"plugin.go": "package min\n\nfunc broken( {\n"})
	list := listJSON(modulePkg(dir, "example.test/min", nil, "plugin.go"))
	_, err := check.Run(context.Background(), check.Options{Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t), Runner: &script{list: list}})
	require.ErrorContains(t, err, "parse")
}

func TestFake_ListErrors(t *testing.T) {
	t.Parallel()
	dir, m, v := minimalCompanion(t, nil)
	_, err := check.Run(context.Background(), check.Options{
		Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t),
		Runner: &script{list: `{"ImportPath":"x","Error":{"Err":"no Go files"}}`},
	})
	require.ErrorContains(t, err, "no Go files")
	_, err = check.Run(context.Background(), check.Options{
		Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t),
		Runner: &script{list: `{"ImportPath": nonsense`},
	})
	require.ErrorContains(t, err, "list packages")
}

func TestFake_ManifestJSONProblems(t *testing.T) {
	t.Parallel()
	dir, m, v := minimalCompanion(t, map[string]string{"client-plugin.json": "{not json"})
	list := listJSON(modulePkg(dir, "example.test/min", nil, "plugin.go"))
	r, err := check.Run(context.Background(), check.Options{Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t), Runner: &script{list: list}})
	require.NoError(t, err)
	assert.Contains(t, strings.Join(findings(r, "manifest", check.Fail), "\n"), "client-plugin.json")

	require.NoError(t, os.Remove(filepath.Join(dir, "client-plugin.json")))
	r, err = check.Run(context.Background(), check.Options{Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t), Runner: &script{list: list}})
	require.NoError(t, err)
	assert.Contains(t, strings.Join(findings(r, "manifest", check.Fail), "\n"), "read client-plugin.json")
}

func TestFake_SourceKind(t *testing.T) {
	t.Parallel()
	dir, m, v := minimalCompanion(t, map[string]string{
		"client-plugin.json": `{"name":"othersim","kind":"companion","interface_version":1}`,
	})
	m.Kind = manifest.KindSource
	m.CompanionOf = ""
	m.Simulators = []string{"iracing"}
	list := listJSON(modulePkg(dir, "example.test/min", nil, "plugin.go"))
	r, err := check.Run(context.Background(), check.Options{Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t), Runner: &script{list: list}})
	require.NoError(t, err)
	fails := strings.Join(findings(r, "manifest", check.Fail), "\n")
	assert.Contains(t, fails, `says kind "companion", the marketplace says source`)
	assert.Contains(t, fails, `says "othersim", the marketplace "iracing"`)
}

func serverManifest(calls []string) (*manifest.Manifest, *manifest.Version) {
	m := &manifest.Manifest{
		Name: "demo", Kind: manifest.KindServer, Title: "T", Summary: "A server plugin for the tests.",
		Author: "t", Contact: "t@example.com", Repository: "https://github.com/x/y", Module: "example.test/srv",
		Licence: "MIT", Visibility: manifest.Public, Pricing: manifest.Free, Calls: calls,
		Versions: []manifest.Version{{Tag: "v0.1.0", Approved: "2026-09-24", Reviewer: "r", InterfaceVersion: 3, Status: manifest.StatusApproved}},
	}
	return m, &m.Versions[0]
}

func TestFake_ServerBranches(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"go.mod":           "module example.test/srv\n\ngo 1.26\n",
		"LICENSE":          "x",
		"cmd/demo/main.go": "package main\n\nfunc main() {}\n",
	}
	mainPkg := func(dir string) map[string]any {
		return modulePkg(filepath.Join(dir, "cmd", "demo"), "example.test/srv", nil, "main.go")
	}

	t.Run("no binary in plugin.json", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{"plugin.json": `{"name":"demo","interface_version":3,"capabilities":{"network":false}}`}
		for k, val := range base {
			files[k] = val
		}
		dir := writeModule(t, files)
		m, v := serverManifest([]string{})
		r, err := check.Run(context.Background(), check.Options{Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t), Runner: &script{list: listJSON(mainPkg(dir))}})
		require.NoError(t, err)
		all := strings.Join(details(r), "\n")
		assert.Contains(t, all, "no binary named")
		assert.Contains(t, all, "cannot tell which binary")
	})

	t.Run("binary named but no cmd package", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{"plugin.json": `{"name":"demo","interface_version":3,"binary":"ghost","capabilities":{"network":false}}`}
		for k, val := range base {
			files[k] = val
		}
		dir := writeModule(t, files)
		m, v := serverManifest([]string{})
		r, err := check.Run(context.Background(), check.Options{Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t), Runner: &script{list: listJSON(mainPkg(dir))}})
		require.NoError(t, err)
		assert.Contains(t, strings.Join(findings(r, "reproducible", check.Fail), "\n"), "no ./cmd/ghost package")
	})

	t.Run("builds differ, build fails, output missing, unsupported interface", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{"plugin.json": `{"name":"demo","interface_version":9,"binary":"demo","capabilities":{"network":false}}`}
		for k, val := range base {
			files[k] = val
		}
		dir := writeModule(t, files)
		m, v := serverManifest([]string{})
		v.InterfaceVersion = 9
		list := listJSON(mainPkg(dir))

		r, err := check.Run(context.Background(), check.Options{
			Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t),
			Runner: &script{list: list, buildOut: func(n int) string { return fmt.Sprint("build ", n) }},
		})
		require.NoError(t, err)
		all := strings.Join(details(r), "\n")
		assert.Contains(t, all, "two builds of ./cmd/demo differ")
		assert.Contains(t, all, "interface version 9 is not one the current server accepts")

		r, err = check.Run(context.Background(), check.Options{
			Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t),
			Runner: &script{list: list, buildOut: func(int) string { return "same" }},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, findings(r, "reproducible", check.Info))

		r, err = check.Run(context.Background(), check.Options{
			Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t),
			Runner: &script{list: list},
		})
		require.NoError(t, err)
		assert.Contains(t, strings.Join(findings(r, "reproducible", check.Fail), "\n"), "open", "a build that wrote nothing cannot be hashed")

		r, err = check.Run(context.Background(), check.Options{
			Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t),
			Runner: &script{list: list, fail: map[string]error{"build": errors.New("exit 1")}},
		})
		require.NoError(t, err)
		assert.Contains(t, strings.Join(findings(r, "reproducible", check.Fail), "\n"), "build 1:")
	})
}

func TestFake_ManyHostOccurrences(t *testing.T) {
	t.Parallel()
	dir, m, v := minimalCompanion(t, map[string]string{
		"plugin.go": "package min\n\nvar a = \"x.evil.example\"\nvar b = \"x.evil.example\"\nvar c = \"x.evil.example\"\nvar d = \"x.evil.example\"\nvar e = \"lap.png\"\nvar f = \"voice.speak\"\nvar g = \"vendor.io\"\n",
	})
	list := listJSON(modulePkg(dir, "example.test/min", nil, "plugin.go"))
	r, err := check.Run(context.Background(), check.Options{Manifest: m, Version: v, Dir: dir, Policy: loadPolicy(t), Runner: &script{list: list}})
	require.NoError(t, err)
	hosts := strings.Join(findings(r, "hosts", check.Fail), "\n")
	assert.Contains(t, hosts, "and 1 more")
	assert.NotContains(t, hosts, "lap.png", "a file name is not a host")
	assert.NotContains(t, hosts, "voice.speak", "a request kind is two labels with no top-level domain")
	assert.Contains(t, hosts, "vendor.io", "two labels with a common top-level domain are a host")
}
