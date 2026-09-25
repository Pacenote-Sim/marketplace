package artifacts_test

import (
	"archive/zip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pacenote-sim/marketplace/internal/artifacts"
	"github.com/pacenote-sim/marketplace/internal/check"
	"github.com/pacenote-sim/marketplace/internal/manifest"
	"github.com/pacenote-sim/marketplace/internal/policy"
)

func fixtureServer(t *testing.T) (*manifest.Manifest, string) {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":                    "module example.test/srv\n\ngo 1.26\n",
		"LICENSE":                   "MIT, for the test.\n",
		"plugin.json":               `{"name":"demo","version":"0.1.0","interface_version":3,"binary":"demo"}`,
		"cmd/demo/main.go":          "package main\n\nfunc main() {}\n",
		"migrations/00001_init.sql": "CREATE TABLE t (id int);\n",
	}
	for name, body := range files {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}
	m := &manifest.Manifest{
		Name: "demo", Kind: manifest.KindServer, Module: "example.test/srv", Calls: []string{},
		Versions: []manifest.Version{
			{Tag: "v0.1.0", Approved: "2026-09-24", Reviewer: "r", InterfaceVersion: 3, Status: manifest.StatusApproved},
			{Tag: "v0.2.0", Approved: "2026-09-25", Reviewer: "r", InterfaceVersion: 3, Status: manifest.StatusWithdrawn, Notes: "x"},
		},
	}
	return m, dir
}

func loadPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Load(filepath.Join("..", "..", "policy"))
	require.NoError(t, err)
	return p
}

func TestBuild(t *testing.T) {
	t.Parallel()
	m, src := fixtureServer(t)
	client := &manifest.Manifest{Name: "client-x", Kind: manifest.KindCompanion}
	out := t.TempDir()
	source := func(_ context.Context, module, tag string) (string, error) {
		assert.Equal(t, "example.test/srv", module)
		assert.Equal(t, "v0.1.0", tag, "only approved versions are built")
		return src, nil
	}
	recs, err := artifacts.Build(context.Background(), artifacts.Options{
		Manifests: []*manifest.Manifest{client, m}, Policy: loadPolicy(t), Runner: check.Exec{}, Source: source,
		OutDir: out, BaseURL: "https://example.com/dl/",
	})
	require.NoError(t, err)
	require.Len(t, recs, 5, "one per server platform")

	win := recs[4]
	assert.Equal(t, "windows", win.OS)
	assert.Equal(t, "demo_0.1.0_windows_amd64.zip", win.File)
	assert.Equal(t, "https://example.com/dl/demo-v0.1.0/demo_0.1.0_windows_amd64.zip", win.URL)
	assert.Len(t, win.SHA256, 64)

	zr, err := zip.OpenReader(filepath.Join(out, "demo-v0.1.0", win.File))
	require.NoError(t, err)
	defer func() { _ = zr.Close() }()
	names := make([]string, 0, len(zr.File))
	for _, f := range zr.File {
		names = append(names, f.Name)
		assert.Equal(t, 2026, f.Modified.Year(), "fixed timestamps, so the zip is reproducible")
	}
	assert.Equal(t, []string{"demo/LICENSE", "demo/demo.exe", "demo/migrations/00001_init.sql", "demo/plugin.json"}, names)

	sums, err := os.ReadFile(filepath.Join(out, "demo-v0.1.0", "checksums.txt"))
	require.NoError(t, err)
	assert.Contains(t, string(sums), win.SHA256+"  "+win.File)

	loaded, err := artifacts.Load(filepath.Join(out, "artifacts.json"))
	require.NoError(t, err)
	assert.Len(t, loaded[struct{ Name, Tag string }{"demo", "v0.1.0"}], 5)

	// The same input zips to the same bytes.
	out2 := t.TempDir()
	recs2, err := artifacts.Build(context.Background(), artifacts.Options{
		Manifests: []*manifest.Manifest{m}, Policy: loadPolicy(t), Runner: check.Exec{}, Source: source,
		OutDir: out2, BaseURL: "https://example.com/dl", Only: "demo",
	})
	require.NoError(t, err)
	assert.Equal(t, recs[0].SHA256, recs2[0].SHA256)
}

func TestBuild_Errors(t *testing.T) {
	t.Parallel()
	m, src := fixtureServer(t)
	p := loadPolicy(t)
	ok := func(context.Context, string, string) (string, error) { return src, nil }
	base := artifacts.Options{Manifests: []*manifest.Manifest{m}, Policy: p, Runner: check.Exec{}, Source: ok, BaseURL: "https://x"}

	_, err := artifacts.Build(context.Background(), artifacts.Options{})
	require.Error(t, err)

	o := base
	o.OutDir = t.TempDir()
	o.Source = func(context.Context, string, string) (string, error) { return "", errors.New("no such tag") }
	_, err = artifacts.Build(context.Background(), o)
	require.ErrorContains(t, err, "no such tag")

	o = base
	o.OutDir = t.TempDir()
	o.Runner = failing{}
	_, err = artifacts.Build(context.Background(), o)
	require.ErrorContains(t, err, "build linux/amd64")

	o = base
	o.OutDir = t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, "plugin.json"), []byte(`{"binary":"../evil"}`), 0o600))
	_, err = artifacts.Build(context.Background(), o)
	require.ErrorContains(t, err, "not a plain name")
	require.NoError(t, os.WriteFile(filepath.Join(src, "plugin.json"), []byte(`{`), 0o600))
	_, err = artifacts.Build(context.Background(), o)
	require.ErrorContains(t, err, "plugin.json")
	require.NoError(t, os.Remove(filepath.Join(src, "plugin.json")))
	_, err = artifacts.Build(context.Background(), o)
	require.ErrorContains(t, err, "plugin.json")

	_, err = artifacts.Load(filepath.Join(t.TempDir(), "missing.json"))
	require.Error(t, err)
	bad := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte("{"), 0o600))
	_, err = artifacts.Load(bad)
	require.Error(t, err)
}

type failing struct{}

func (failing) Run(context.Context, string, []string, string, ...string) ([]byte, error) {
	return nil, errors.New("compiler on fire")
}

func TestBuild_OutputErrors(t *testing.T) {
	t.Parallel()
	m, src := fixtureServer(t)
	p := loadPolicy(t)
	ok := func(context.Context, string, string) (string, error) { return src, nil }

	// The output directory is a file: nothing can be created under it.
	blocked := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocked, []byte("x"), 0o600))
	_, err := artifacts.Build(context.Background(), artifacts.Options{
		Manifests: []*manifest.Manifest{m}, Policy: p, Runner: check.Exec{}, Source: ok, OutDir: blocked, BaseURL: "https://x",
	})
	require.ErrorContains(t, err, "release dir")

	// A runner that says it built but wrote nothing: the zip cannot be filled.
	_, err = artifacts.Build(context.Background(), artifacts.Options{
		Manifests: []*manifest.Manifest{m}, Policy: p, Runner: silent{}, Source: ok, OutDir: t.TempDir(), BaseURL: "https://x",
	})
	require.ErrorContains(t, err, "open")

	// No server plugins at all: an empty artifacts.json, no error.
	out := t.TempDir()
	recs, err := artifacts.Build(context.Background(), artifacts.Options{
		Manifests: []*manifest.Manifest{{Name: "client-x", Kind: manifest.KindCompanion}}, Policy: p, Runner: check.Exec{}, Source: ok, OutDir: out, BaseURL: "https://x",
	})
	require.NoError(t, err)
	assert.Empty(t, recs)
	loaded, err := artifacts.Load(filepath.Join(out, "artifacts.json"))
	require.NoError(t, err)
	assert.Empty(t, loaded)

	// Other licence file names are picked up too.
	require.NoError(t, os.Rename(filepath.Join(src, "LICENSE"), filepath.Join(src, "COPYING")))
	out = t.TempDir()
	recs, err = artifacts.Build(context.Background(), artifacts.Options{
		Manifests: []*manifest.Manifest{m}, Policy: p, Runner: check.Exec{}, Source: ok, OutDir: out, BaseURL: "https://x",
	})
	require.NoError(t, err)
	zr, err := zip.OpenReader(filepath.Join(out, "demo-v0.1.0", recs[0].File))
	require.NoError(t, err)
	defer func() { _ = zr.Close() }()
	assert.Equal(t, "demo/COPYING", zr.File[0].Name)
}

// silent claims success and writes no output file.
type silent struct{}

func (silent) Run(context.Context, string, []string, string, ...string) ([]byte, error) {
	return nil, nil
}

func TestBuild_UnwritableOutput(t *testing.T) {
	t.Parallel()
	m, src := fixtureServer(t)
	p := loadPolicy(t)
	ok := func(context.Context, string, string) (string, error) { return src, nil }
	none := []*manifest.Manifest{{Name: "client-x", Kind: manifest.KindCompanion}}

	// The output path is a file, and there is nothing to build first.
	blocked := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocked, []byte("x"), 0o600))
	_, err := artifacts.Build(context.Background(), artifacts.Options{Manifests: none, Policy: p, Runner: check.Exec{}, Source: ok, OutDir: blocked, BaseURL: "https://x"})
	require.ErrorContains(t, err, "out dir")

	// The output directory exists but cannot be written to.
	readOnly := filepath.Join(t.TempDir(), "ro")
	require.NoError(t, os.Mkdir(readOnly, 0o500))
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0o700) })
	_, err = artifacts.Build(context.Background(), artifacts.Options{Manifests: none, Policy: p, Runner: check.Exec{}, Source: ok, OutDir: readOnly, BaseURL: "https://x"})
	require.ErrorContains(t, err, "artifacts.json")

	// The release directory exists and cannot take a zip.
	out := t.TempDir()
	rel := filepath.Join(out, "demo-v0.1.0")
	require.NoError(t, os.Mkdir(rel, 0o500))
	t.Cleanup(func() { _ = os.Chmod(rel, 0o700) })
	_, err = artifacts.Build(context.Background(), artifacts.Options{Manifests: []*manifest.Manifest{m}, Policy: p, Runner: check.Exec{}, Source: ok, OutDir: out, BaseURL: "https://x"})
	require.ErrorContains(t, err, "create")
}
