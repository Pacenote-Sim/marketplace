// Package artifacts builds the server-plugin packages the marketplace serves:
// one zip per approved tag per platform, holding the folder an operator drops
// into pacenote-data/plugins/.
//
// Pacenote's CI builds these from the reviewed tag. An author's own release is
// never served, so what an operator installs is provably what was reviewed.
// The build is reproducible, and so is the zip: fixed timestamps, sorted
// entries, no extra attributes.
package artifacts

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pacenote-sim/marketplace/internal/check"
	"github.com/pacenote-sim/marketplace/internal/index"
	"github.com/pacenote-sim/marketplace/internal/manifest"
	"github.com/pacenote-sim/marketplace/internal/policy"
)

// Record is one built package, as written to artifacts.json.
type Record struct {
	Name   string `json:"name"`
	Tag    string `json:"tag"`
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	URL    string `json:"url"`
}

// Options is what a build needs.
type Options struct {
	Manifests []*manifest.Manifest
	Policy    *policy.Policy
	Runner    check.Runner
	// Source returns the module's directory at the tag. Fetch through the
	// proxy in CI; a fixture in the tests.
	Source func(ctx context.Context, module, tag string) (string, error)
	// OutDir receives <name>-<tag>/<name>_<tag>_<os>_<arch>.zip, a
	// checksums.txt beside each set, and artifacts.json at the top.
	OutDir string
	// BaseURL is where the release assets end up:
	// <BaseURL>/<name>-<tag>/<file>.
	BaseURL string
	// Only limits the build to one plugin name, for a manual run.
	Only string
}

// zipTime is the timestamp every entry carries, so two builds zip the same.
var zipTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Build packages every approved version of every server plugin.
func Build(ctx context.Context, o Options) ([]Record, error) {
	if o.Policy == nil || o.Runner == nil || o.Source == nil || o.OutDir == "" || o.BaseURL == "" {
		return nil, fmt.Errorf("artifacts: policy, runner, source, out dir and base url are all required")
	}
	var records []Record
	for _, m := range o.Manifests {
		if m.Kind != manifest.KindServer || (o.Only != "" && m.Name != o.Only) {
			continue
		}
		for _, v := range m.Versions {
			if v.Status != manifest.StatusApproved {
				continue
			}
			recs, err := buildOne(ctx, o, m, v)
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", m.Name, v.Tag, err)
			}
			records = append(records, recs...)
		}
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("artifacts.json: %w", err)
	}
	if err := os.MkdirAll(o.OutDir, 0o750); err != nil {
		return nil, fmt.Errorf("out dir: %w", err)
	}
	//nolint:gosec // artifacts.json is a build output, read by the next step
	if err := os.WriteFile(filepath.Join(o.OutDir, "artifacts.json"), append(data, '\n'), 0o644); err != nil {
		return nil, fmt.Errorf("artifacts.json: %w", err)
	}
	return records, nil
}

func buildOne(ctx context.Context, o Options, m *manifest.Manifest, v manifest.Version) ([]Record, error) {
	src, err := o.Source(ctx, m.Module, v.Tag)
	if err != nil {
		return nil, err
	}
	binary, err := binaryName(src)
	if err != nil {
		return nil, err
	}
	release := m.Name + "-" + v.Tag
	dir := filepath.Join(o.OutDir, release)
	if merr := os.MkdirAll(dir, 0o750); merr != nil {
		return nil, fmt.Errorf("release dir: %w", merr)
	}
	tmp, err := os.MkdirTemp("", "marketplace-artifacts-")
	if err != nil {
		return nil, fmt.Errorf("temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	var (
		records []Record
		sums    []string
	)
	for _, pl := range o.Policy.PlatformsFor(m.Kind) {
		exe := binary
		if pl.OS == "windows" {
			exe += ".exe"
		}
		built := filepath.Join(tmp, pl.OS+"_"+pl.Arch, exe)
		env := []string{"CGO_ENABLED=0", "GOOS=" + pl.OS, "GOARCH=" + pl.Arch, "GOFLAGS=-trimpath -buildvcs=false"}
		if _, err := o.Runner.Run(ctx, src, env, "go", "build", "-ldflags=-s -w", "-o", built, "./cmd/"+binary); err != nil {
			return nil, fmt.Errorf("build %s: %w", pl, err)
		}
		file := fmt.Sprintf("%s_%s_%s_%s.zip", m.Name, strings.TrimPrefix(v.Tag, "v"), pl.OS, pl.Arch)
		out := filepath.Join(dir, file)
		if err := writeZip(out, m.Name, src, built, exe); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		sum, err := fileSHA256(out)
		if err != nil {
			return nil, err
		}
		sums = append(sums, sum+"  "+file)
		records = append(records, Record{
			Name: m.Name, Tag: v.Tag, OS: pl.OS, Arch: pl.Arch, File: file, SHA256: sum,
			URL: strings.TrimSuffix(o.BaseURL, "/") + "/" + release + "/" + file,
		})
	}
	//nolint:gosec // checksums.txt is published beside the zips
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(strings.Join(sums, "\n")+"\n"), 0o644); err != nil {
		return nil, fmt.Errorf("checksums: %w", err)
	}
	return records, nil
}

// binaryName reads plugin.json for the binary the server runs; the main
// package is ./cmd/<binary> by convention, as the check step also assumes.
func binaryName(src string) (string, error) {
	data, err := os.ReadFile(filepath.Join(src, "plugin.json")) //nolint:gosec // the reviewed module's own manifest
	if err != nil {
		return "", fmt.Errorf("plugin.json: %w", err)
	}
	var p struct {
		Binary string `json:"binary"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return "", fmt.Errorf("plugin.json: %w", err)
	}
	if p.Binary == "" || strings.ContainsAny(p.Binary, `/\`) {
		return "", fmt.Errorf("plugin.json: binary %q is not a plain name", p.Binary)
	}
	return p.Binary, nil
}

// writeZip lays out <name>/<exe>, <name>/plugin.json, <name>/migrations/…
// and <name>/LICENSE, the folder the server's plugin directory takes as is.
func writeZip(out, name, src, built, exe string) error {
	f, err := os.Create(out) //nolint:gosec // a zip in the build's own output directory
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	defer func() { _ = f.Close() }()
	zw := zip.NewWriter(f)

	type entry struct{ path, from string }
	entries := []entry{
		{path.Join(name, exe), built},
		{path.Join(name, "plugin.json"), filepath.Join(src, "plugin.json")},
	}
	for _, lic := range []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING"} {
		if _, err := os.Stat(filepath.Join(src, lic)); err == nil {
			entries = append(entries, entry{path.Join(name, lic), filepath.Join(src, lic)})
			break
		}
	}
	migrations := filepath.Join(src, "migrations")
	if err := filepath.WalkDir(migrations, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // no migrations directory is fine
		}
		rel, _ := filepath.Rel(src, p)
		entries = append(entries, entry{path.Join(name, filepath.ToSlash(rel)), p})
		return nil
	}); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })

	for _, e := range entries {
		mode := fs.FileMode(0o644)
		if e.path == path.Join(name, exe) {
			mode = 0o755
		}
		h := &zip.FileHeader{Name: e.path, Method: zip.Deflate, Modified: zipTime}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return fmt.Errorf("%s: %w", e.path, err)
		}
		if err := copyFile(w, e.from); err != nil {
			return fmt.Errorf("%s: %w", e.path, err)
		}
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("finish zip: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close zip: %w", err)
	}
	return nil
}

func copyFile(w io.Writer, name string) error {
	r, err := os.Open(name) //nolint:gosec // a file of the reviewed module, or the binary just built
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = r.Close() }()
	if _, err := io.Copy(w, r); err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	return nil
}

func fileSHA256(name string) (string, error) {
	r, err := os.Open(name) //nolint:gosec // the zip just written
	if err != nil {
		return "", fmt.Errorf("open %s: %w", name, err)
	}
	defer func() { _ = r.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("hash %s: %w", name, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Load reads artifacts.json into the map the index builder takes.
func Load(name string) (map[index.ArtifactKey][]index.Artifact, error) {
	data, err := os.ReadFile(name) //nolint:gosec // the build output named on the command line
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	var records []Record
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return ToMap(records), nil
}

// ToMap groups records by plugin and tag.
func ToMap(records []Record) map[index.ArtifactKey][]index.Artifact {
	out := map[index.ArtifactKey][]index.Artifact{}
	for _, r := range records {
		k := index.ArtifactKey{Name: r.Name, Tag: r.Tag}
		out[k] = append(out[k], index.Artifact{OS: r.OS, Arch: r.Arch, URL: r.URL, SHA256: r.SHA256})
	}
	return out
}
