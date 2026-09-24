// Package policy reads the rules the checks apply: which contract versions the
// current client and server accept, which standard packages a client plugin
// may import, which symbols it may never touch, and which platforms every
// plugin has to build for.
//
// The rules live in policy/*.yaml in the marketplace repository so that a
// plugin author can read them before writing a line, and so that changing one
// is a reviewed pull request like any other.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/pacenote-sim/marketplace/internal/manifest"
)

// Platform is one GOOS/GOARCH pair a plugin has to build for.
type Platform struct {
	OS   string `yaml:"os"`
	Arch string `yaml:"arch"`
}

func (p Platform) String() string { return p.OS + "/" + p.Arch }

// Imports is the import policy for one client-plugin kind.
type Imports struct {
	// Std is every standard-library package the kind may import without a
	// reason. Anything standard that is not here needs an imports_allow entry.
	Std []string `yaml:"std"`
	// DenySymbols are uses that fail whatever the import policy says: the
	// package, and the identifiers in it that dial, listen or run things.
	DenySymbols map[string][]string `yaml:"deny_symbols"`
}

// Policy is everything under policy/.
type Policy struct {
	// Interfaces are the contract versions the current client and server
	// accept, by contract module.
	Interfaces struct {
		Plugin       []int `yaml:"plugin"`
		ClientPlugin []int `yaml:"clientplugin"`
	} `yaml:"interfaces"`
	// Platforms a plugin of each kind has to build for, CGO_ENABLED=0.
	Platforms struct {
		Server []Platform `yaml:"server"`
		Client []Platform `yaml:"client"`
	} `yaml:"platforms"`
	// Contracts are the modules a client plugin may always import.
	Contracts []string `yaml:"contracts"`
	Companion Imports  `yaml:"companion"`
	Source    Imports  `yaml:"source"`
	// KnownHosts are literals the host scan never reports: documentation
	// links and the like, the same for every plugin.
	KnownHosts []string `yaml:"known_hosts"`
}

// Load reads policy/*.yaml from dir. Every file is decoded into the same
// Policy, so the rules can be split by topic.
func Load(dir string) (*Policy, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("glob %s: %w", dir, err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no policy files in %s", dir)
	}
	var p Policy
	for _, path := range paths {
		data, err := os.ReadFile(path) //nolint:gosec // a policy file under the directory given on the command line
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		dec.KnownFields(true)
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return &p, nil
}

// Supports reports whether the kind's contract accepts the interface version.
func (p *Policy) Supports(kind manifest.Kind, version int) bool {
	list := p.Interfaces.ClientPlugin
	if kind == manifest.KindServer {
		list = p.Interfaces.Plugin
	}
	for _, v := range list {
		if v == version {
			return true
		}
	}
	return false
}

// PlatformsFor is the build matrix for the kind.
func (p *Policy) PlatformsFor(kind manifest.Kind) []Platform {
	if kind == manifest.KindServer {
		return p.Platforms.Server
	}
	return p.Platforms.Client
}

// ImportsFor is the import policy for a client-plugin kind, or nil for a
// server plugin, which has no import policy: it is its own process.
func (p *Policy) ImportsFor(kind manifest.Kind) *Imports {
	switch kind {
	case manifest.KindCompanion:
		return &p.Companion
	case manifest.KindSource:
		return &p.Source
	default:
		return nil
	}
}

// IsContract reports whether the module is one of the plugin contracts, or the
// protocol they rest on.
func (p *Policy) IsContract(modulePath string) bool {
	for _, c := range p.Contracts {
		if modulePath == c {
			return true
		}
	}
	return false
}
