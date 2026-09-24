// Package manifest reads and validates the one file a plugin has in the
// marketplace repository: plugins/<name>.yaml.
//
// The manifest holds what the marketplace needs to list, fetch and review a
// plugin. It does not repeat what the plugin's own plugin.json or
// client-plugin.json already says; the check step reads those from the tag and
// confirms the two agree.
package manifest

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// Kind is what a plugin is. A server plugin runs beside the server as its own
// process; a source and a companion are compiled into the client.
type Kind string

// The three kinds.
const (
	KindServer    Kind = "server"
	KindSource    Kind = "source"
	KindCompanion Kind = "companion"
)

// Client reports whether the kind is compiled into the client.
func (k Kind) Client() bool { return k == KindSource || k == KindCompanion }

// Status is where an approved version stands.
type Status string

// The two statuses. A withdrawn version stays in the index so a server can warn
// about a copy it already has.
const (
	StatusApproved  Status = "approved"
	StatusWithdrawn Status = "withdrawn"
)

// Visibility says whether the source is public. Private means Pacenote's
// review account has read access and Pacenote's build service builds it.
type Visibility string

// The two visibilities.
const (
	Public  Visibility = "public"
	Private Visibility = "private"
)

// Pricing is the one word an operator sees before installing. Money is the
// plugin's business; the marketplace only says which it is.
type Pricing string

// The two pricings.
const (
	Free Pricing = "free"
	Paid Pricing = "paid"
)

// Reasoned is a value the author has to justify: a dependency outside the
// standard library, or a standard package the policy denies by default.
type Reasoned struct {
	Value  string `yaml:"value"`
	Reason string `yaml:"reason"`
}

// Version is one approved tag.
type Version struct {
	Tag              string `yaml:"tag"`
	Approved         string `yaml:"approved"`
	Reviewer         string `yaml:"reviewer"`
	InterfaceVersion int    `yaml:"interface_version"`
	Status           Status `yaml:"status"`
	Notes            string `yaml:"notes,omitempty"`
}

// Manifest is plugins/<name>.yaml.
type Manifest struct {
	Name         string     `yaml:"name"`
	Kind         Kind       `yaml:"kind"`
	Title        string     `yaml:"title"`
	Summary      string     `yaml:"summary"`
	Author       string     `yaml:"author"`
	Contact      string     `yaml:"contact"`
	Repository   string     `yaml:"repository"`
	Module       string     `yaml:"module"`
	Licence      string     `yaml:"licence"`
	Visibility   Visibility `yaml:"visibility"`
	Pricing      Pricing    `yaml:"pricing"`
	Website      string     `yaml:"website,omitempty"`
	Simulators   []string   `yaml:"simulators,omitempty"`
	Calls        []string   `yaml:"calls"`
	CompanionOf  string     `yaml:"companion_of,omitempty"`
	Dependencies []Reasoned `yaml:"dependencies,omitempty"`
	ImportsAllow []Reasoned `yaml:"imports_allow,omitempty"`
	NotHosts     []string   `yaml:"not_hosts,omitempty"`
	Versions     []Version  `yaml:"versions"`
}

// Load reads one manifest. Unknown fields are an error: a misspelt field would
// otherwise be silently ignored and the plugin listed without it.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path) //nolint:gosec // a manifest path given on the command line
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	m, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// Parse decodes a manifest from YAML.
func Parse(data []byte) (*Manifest, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return &m, nil
}

// LoadDir reads every plugins/*.yaml, sorted by name, and validates each
// against its file name. It returns every manifest that parsed and every error
// found, so a pull request sees all of its problems at once.
func LoadDir(dir string) ([]*Manifest, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("glob %s: %w", dir, err)
	}
	sort.Strings(paths)
	var (
		out  []*Manifest
		errs []error
	)
	for _, p := range paths {
		m, err := Load(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := m.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
		}
		if stem := strings.TrimSuffix(filepath.Base(p), ".yaml"); stem != m.Name {
			errs = append(errs, fmt.Errorf("%s: file is named %q but the manifest says %q", p, stem, m.Name))
		}
		out = append(out, m)
	}
	errs = append(errs, Collisions(out)...)
	return out, errors.Join(errs...)
}

var (
	nameRe  = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Validate checks everything that can be checked without the plugin's source.
func (m *Manifest) Validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if !nameRe.MatchString(m.Name) || len(m.Name) < 2 || len(m.Name) > 40 {
		fail("name %q: lower-case letters, digits and single hyphens, 2 to 40 characters, starting with a letter", m.Name)
	}
	switch m.Kind {
	case KindServer, KindSource, KindCompanion:
	default:
		fail("kind %q: one of server, source, companion", m.Kind)
	}
	if m.Kind.Client() && !strings.HasPrefix(m.Name, "client-") {
		fail("name %q: a client plugin's marketplace name starts with client-, like its repository", m.Name)
	}
	if m.Kind == KindServer && strings.HasPrefix(m.Name, "client-") {
		fail("name %q: a server plugin's name does not start with client-", m.Name)
	}
	if n := len(m.Title); n == 0 || n > 60 {
		fail("title: 1 to 60 characters")
	}
	if n := len(m.Summary); n < 10 || n > 160 {
		fail("summary: 10 to 160 characters, one sentence an operator reads in the list")
	}
	if m.Author == "" {
		fail("author: required")
	}
	if err := checkContact(m.Contact); err != nil {
		fail("contact: %w", err)
	}
	if err := checkHTTPS(m.Repository); err != nil {
		fail("repository: %w", err)
	}
	if err := module.CheckPath(m.Module); err != nil {
		fail("module: %w", err)
	}
	if m.Licence == "" {
		fail("licence: required, an SPDX identifier such as GPL-3.0-or-later or Apache-2.0")
	}
	switch m.Visibility {
	case Public, Private:
	default:
		fail("visibility %q: public or private", m.Visibility)
	}
	switch m.Pricing {
	case Free, Paid:
	default:
		fail("pricing %q: free or paid", m.Pricing)
	}
	if m.Website != "" {
		if err := checkHTTPS(m.Website); err != nil {
			fail("website: %w", err)
		}
	}
	if m.Calls == nil {
		fail("calls: required; an empty list means the plugin dials nothing")
	}
	for _, h := range m.Calls {
		if err := checkHost(h); err != nil {
			fail("calls: %w", err)
		}
	}
	for _, h := range m.NotHosts {
		if h == "" {
			fail("not_hosts: empty entry")
		}
	}
	errs = append(errs, m.validateKind()...)
	for i, d := range m.Dependencies {
		if err := module.CheckPath(d.Value); err != nil {
			fail("dependencies[%d]: %w", i, err)
		}
		if d.Reason == "" {
			fail("dependencies[%d] %s: a reason is required", i, d.Value)
		}
	}
	for i, p := range m.ImportsAllow {
		if p.Value == "" || p.Reason == "" {
			fail("imports_allow[%d]: a package and a reason are required", i)
		}
	}
	errs = append(errs, m.validateVersions()...)
	return errors.Join(errs...)
}

func (m *Manifest) validateKind() []error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	switch m.Kind {
	case KindSource:
		if len(m.Simulators) != 1 {
			fail("simulators: a source names exactly the one simulator it reads")
		}
		if m.CompanionOf != "" {
			fail("companion_of: a source has no server half")
		}
	case KindCompanion:
		if m.CompanionOf == "" {
			fail("companion_of: a companion names its server plugin")
		} else if !nameRe.MatchString(m.CompanionOf) || strings.HasPrefix(m.CompanionOf, "client-") {
			fail("companion_of %q: a server plugin's marketplace name", m.CompanionOf)
		}
		if len(m.Simulators) != 0 {
			fail("simulators: only a source names a simulator")
		}
	case KindServer:
		if len(m.Simulators) != 0 {
			fail("simulators: only a source names a simulator")
		}
		if m.CompanionOf != "" && !strings.HasPrefix(m.CompanionOf, "client-") {
			fail("companion_of %q: a server plugin names its client half, whose name starts with client-", m.CompanionOf)
		}
		if len(m.ImportsAllow) != 0 {
			fail("imports_allow: only client plugins have an import policy")
		}
	}
	return errs
}

func (m *Manifest) validateVersions() []error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if len(m.Versions) == 0 {
		fail("versions: at least one; a name is taken by its first approved version, not before")
		return errs
	}
	seen := map[string]bool{}
	for i, v := range m.Versions {
		if !semver.IsValid(v.Tag) || semver.Canonical(v.Tag) != v.Tag {
			fail("versions[%d].tag %q: a canonical semantic version tag such as v1.2.3", i, v.Tag)
		}
		if seen[v.Tag] {
			fail("versions[%d].tag %q: listed twice", i, v.Tag)
		}
		seen[v.Tag] = true
		if i > 0 && semver.Compare(m.Versions[i-1].Tag, v.Tag) >= 0 {
			fail("versions[%d].tag %q: versions are listed oldest first", i, v.Tag)
		}
		if _, err := time.Parse("2006-01-02", v.Approved); err != nil {
			fail("versions[%d].approved %q: a date, YYYY-MM-DD", i, v.Approved)
		}
		if v.Reviewer == "" {
			fail("versions[%d].reviewer: who read it", i)
		}
		if v.InterfaceVersion <= 0 {
			fail("versions[%d].interface_version: the contract version the tag was built against", i)
		}
		switch v.Status {
		case StatusApproved:
		case StatusWithdrawn:
			if v.Notes == "" {
				fail("versions[%d]: a withdrawn version says why in notes", i)
			}
		default:
			fail("versions[%d].status %q: approved or withdrawn", i, v.Status)
		}
	}
	return errs
}

// Latest is the newest version that is still approved, or nil.
func (m *Manifest) Latest() *Version {
	for i := len(m.Versions) - 1; i >= 0; i-- {
		if m.Versions[i].Status == StatusApproved {
			return &m.Versions[i]
		}
	}
	return nil
}

// Collisions finds names that a person would read as the same: identical after
// dropping hyphens and mapping look-alike digits. "client-voice" and
// "c1ient-v0ice" collide; so do "visual-telemetry" and "visualtelemetry".
func Collisions(ms []*Manifest) []error {
	byKey := map[string]string{}
	var errs []error
	for _, m := range ms {
		k := Normalise(m.Name)
		if other, ok := byKey[k]; ok && other != m.Name {
			errs = append(errs, fmt.Errorf("names %q and %q read as the same name", other, m.Name))
			continue
		}
		byKey[k] = m.Name
	}
	return errs
}

var lookalike = strings.NewReplacer("-", "", "0", "o", "1", "l", "3", "e", "5", "s", "7", "t", "8", "b")

// Normalise reduces a name to the form Collisions compares.
func Normalise(name string) string { return lookalike.Replace(strings.ToLower(name)) }

func checkContact(s string) error {
	if s == "" {
		return errors.New("required, an email address or an https URL")
	}
	if strings.Contains(s, "@") {
		if _, err := mail.ParseAddress(s); err != nil {
			return fmt.Errorf("%q is not an email address", s)
		}
		return nil
	}
	return checkHTTPS(s)
}

func checkHTTPS(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%q is not an https URL", s)
	}
	return nil
}

func checkHost(h string) error {
	if h == "" || strings.ContainsAny(h, "/:@ ") || h != strings.ToLower(h) {
		return fmt.Errorf("%q: a bare lower-case host name, no scheme, port or path", h)
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%q: a host name has at least two labels", h)
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return fmt.Errorf("%q: label %q is not valid", h, l)
		}
	}
	return nil
}
