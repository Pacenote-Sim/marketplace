package check

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/pacenote-sim/marketplace/internal/manifest"
)

// Fetch downloads module@tag through the module proxy and returns the
// directory the toolchain unpacked it into. That directory is read-only, which
// is right: nothing a check does may change what was reviewed.
func Fetch(ctx context.Context, r Runner, module, tag string) (string, error) {
	out, err := r.Run(ctx, ".", []string{"GOFLAGS=-mod=mod"}, "go", "mod", "download", "-json", module+"@"+tag)
	var info struct{ Dir, Error string }
	// go mod download prints the JSON even when it exits non-zero, with Error set.
	if jerr := json.Unmarshal(bytes.TrimSpace(out), &info); jerr != nil {
		if err != nil {
			return "", fmt.Errorf("fetch %s@%s: %w", module, tag, err)
		}
		return "", fmt.Errorf("fetch %s@%s: unexpected output: %s", module, tag, out)
	}
	if info.Error != "" {
		return "", fmt.Errorf("fetch %s@%s: %s", module, tag, info.Error)
	}
	if info.Dir == "" {
		return "", fmt.Errorf("fetch %s@%s: no directory in the download report", module, tag)
	}
	return info.Dir, nil
}

// pluginJSON is what both plugin.json and client-plugin.json share, plus the
// fields each has that the checks care about.
type pluginJSON struct {
	Name             string `json:"name"`
	Kind             string `json:"kind"`
	InterfaceVersion int    `json:"interface_version"`
	ServerPlugin     string `json:"server_plugin"`
	Binary           string `json:"binary"`
	Capabilities     struct {
		Network bool     `json:"network"`
		Calls   []string `json:"calls"`
	} `json:"capabilities"`
}

func readPluginJSON(o Options) (*pluginJSON, string, error) {
	name := "client-plugin.json"
	if o.Manifest.Kind == manifest.KindServer {
		name = "plugin.json"
	}
	data, err := readFile(o.Dir + "/" + name)
	if err != nil {
		return nil, name, err
	}
	var p pluginJSON
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, name, fmt.Errorf("%s: %w", name, err)
	}
	return &p, name, nil
}

// checkPluginManifest confirms the plugin's own manifest and the marketplace
// one describe the same plugin. The marketplace repeats nothing the plugin
// already says, so agreement is the whole check.
func checkPluginManifest(r *Report, o Options) {
	p, name, err := readPluginJSON(o)
	if err != nil {
		r.add("manifest", Fail, "%v", err)
		return
	}
	m := o.Manifest
	switch m.Kind {
	case manifest.KindServer:
		if p.Name != m.Name {
			r.add("manifest", Fail, "%s names the plugin %q, the marketplace %q", name, p.Name, m.Name)
		}
		if p.Binary == "" {
			r.add("manifest", Fail, "%s: no binary named; the server needs to know what to run", name)
		}
		declared := append([]string{}, p.Capabilities.Calls...)
		if !sameSet(declared, m.Calls) {
			r.add("manifest", Fail, "%s declares calls %v, the marketplace %v; the two lists must match", name, declared, m.Calls)
		}
		if p.Capabilities.Network != (len(m.Calls) > 0) {
			r.add("manifest", Fail, "%s says network=%v but the marketplace lists %d hosts", name, p.Capabilities.Network, len(m.Calls))
		}
	case manifest.KindSource:
		if p.Kind != "source" {
			r.add("manifest", Fail, "%s says kind %q, the marketplace says source", name, p.Kind)
		}
		if len(m.Simulators) == 1 && p.Name != m.Simulators[0] {
			r.add("manifest", Fail, "a source is named after its simulator: %s says %q, the marketplace %q", name, p.Name, m.Simulators[0])
		}
	case manifest.KindCompanion:
		if p.Kind != "companion" {
			r.add("manifest", Fail, "%s says kind %q, the marketplace says companion", name, p.Kind)
		}
		if p.Name != m.CompanionOf || p.ServerPlugin != m.CompanionOf {
			r.add("manifest", Fail, "a companion is named after its server plugin: %s says name %q, server_plugin %q; the marketplace says %q", name, p.Name, p.ServerPlugin, m.CompanionOf)
		}
	}
	if p.InterfaceVersion != o.Version.InterfaceVersion {
		r.add("manifest", Fail, "%s was built against interface version %d, the marketplace says %d", name, p.InterfaceVersion, o.Version.InterfaceVersion)
	}
	if !o.Policy.Supports(m.Kind, p.InterfaceVersion) {
		r.add("manifest", Fail, "interface version %d is not one the current %s accepts", p.InterfaceVersion, hostFor(m.Kind))
	}
	if !r.Failed() {
		r.add("manifest", Info, "%s agrees with the marketplace manifest", name)
	}
}

func hostFor(k manifest.Kind) string {
	if k == manifest.KindServer {
		return "server"
	}
	return "client"
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]bool{}
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			return false
		}
	}
	return true
}

// pkg is what go list -deps -json tells us about one package.
type pkg struct {
	ImportPath string
	Name       string
	Dir        string
	Standard   bool
	Module     *struct{ Path string }
	Imports    []string
	GoFiles    []string
	Error      *struct{ Err string }
}

func (p *pkg) inModule(modulePath string) bool {
	return p.Module != nil && p.Module.Path == modulePath
}

// listPackages lists the plugin's package and everything it depends on, for
// the platform the code will actually run on. A client plugin is listed for
// Windows, where the driver's exe runs; a server plugin for Linux.
func listPackages(ctx context.Context, o Options) ([]*pkg, error) {
	env := []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64"}
	target := "."
	if o.Manifest.Kind.Client() {
		env[1] = "GOOS=windows"
	} else if p, _, err := readPluginJSON(o); err == nil && p.Binary != "" {
		target = "./cmd/" + p.Binary
	}
	out, err := o.Runner.Run(ctx, o.Dir, env, "go", "list", "-deps", "-json=ImportPath,Name,Dir,Standard,Module,Imports,GoFiles,Error", target)
	if err != nil {
		return nil, fmt.Errorf("list packages: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	var pkgs []*pkg
	for {
		var p pkg
		if err := dec.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("list packages: %w", err)
		}
		if p.Error != nil {
			return nil, fmt.Errorf("list packages: %s: %s", p.ImportPath, p.Error.Err)
		}
		pkgs = append(pkgs, &p)
	}
	return pkgs, nil
}
