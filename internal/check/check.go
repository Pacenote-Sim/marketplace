// Package check runs the automated part of a review against one tag of one
// plugin: the plugin's own manifest agrees with the marketplace one, the
// licence is there, the imports obey the policy, every host it dials is
// declared, it builds for every platform with CGO_ENABLED=0, and a server
// plugin builds the same bytes twice.
//
// The checks are the sandbox. Compiled-in code has no other one, so the list
// is public and the reasons are in the findings.
package check

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/pacenote-sim/marketplace/internal/manifest"
	"github.com/pacenote-sim/marketplace/internal/policy"
)

// Severity is what a finding means for the pull request.
type Severity string

// Fail blocks the merge. Warn is shown to the reviewer. Info is a fact.
const (
	Fail Severity = "fail"
	Warn Severity = "warn"
	Info Severity = "info"
)

// Finding is one line of the report.
type Finding struct {
	Check    string
	Severity Severity
	Detail   string
}

func (f Finding) String() string { return fmt.Sprintf("%-4s %-12s %s", f.Severity, f.Check, f.Detail) }

// Report is every finding, in the order the checks ran.
type Report struct{ Findings []Finding }

func (r *Report) add(check string, sev Severity, format string, a ...any) {
	r.Findings = append(r.Findings, Finding{Check: check, Severity: sev, Detail: fmt.Sprintf(format, a...)})
}

// Failed reports whether anything blocks the merge.
func (r *Report) Failed() bool {
	for _, f := range r.Findings {
		if f.Severity == Fail {
			return true
		}
	}
	return false
}

// Runner runs a command. It exists so the checks can be tested without a
// toolchain, and so a test can hand a check exactly the output it wants.
type Runner interface {
	Run(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, error)
}

// Exec is the Runner that runs things.
type Exec struct{}

// Run runs name with args in dir, with env added to the process environment.
// GOWORK is always off: a plugin is checked as a checkout of its own, never as
// part of a workspace that might replace its dependencies.
func (Exec) Run(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // running the toolchain on a reviewed checkout is this type's job
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local"), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Options is what one run needs.
type Options struct {
	Manifest *manifest.Manifest
	Version  *manifest.Version
	// Dir is the module's source at the tag.
	Dir    string
	Policy *policy.Policy
	Runner Runner
	// Vuln runs govulncheck when true. It needs network and the tool.
	Vuln bool
}

// Run runs every check and returns the report. An error is a check that could
// not run at all, not a check that failed.
func Run(ctx context.Context, o Options) (*Report, error) {
	if o.Manifest == nil || o.Version == nil || o.Policy == nil || o.Runner == nil || o.Dir == "" {
		return nil, errors.New("check: manifest, version, policy, runner and dir are all required")
	}
	r := &Report{}
	checkLicence(r, o)
	checkPluginManifest(r, o)
	pkgs, err := listPackages(ctx, o)
	if err != nil {
		return nil, err
	}
	if o.Manifest.Kind.Client() {
		checkImports(r, o, pkgs)
	}
	if err := checkHosts(r, o, pkgs); err != nil {
		return nil, err
	}
	checkBuild(ctx, r, o)
	if o.Manifest.Kind == manifest.KindServer {
		checkReproducible(ctx, r, o)
	}
	if o.Vuln {
		checkVuln(ctx, r, o)
	}
	return r, nil
}

func checkLicence(r *Report, o Options) {
	for _, name := range []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING"} {
		if st, err := os.Stat(o.Dir + "/" + name); err == nil && !st.IsDir() && st.Size() > 0 {
			r.add("licence", Info, "%s present", name)
			return
		}
	}
	r.add("licence", Fail, "no LICENSE file at the module root; the manifest says %s", o.Manifest.Licence)
}
