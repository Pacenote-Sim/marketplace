// Command marketplace is what the marketplace repository's CI runs, and what a
// plugin author can run before opening a pull request.
//
//	marketplace validate [plugins/...]      the manifests, and the names against each other
//	marketplace check plugins/<name>.yaml   one plugin's newest approved tag, fetched from the proxy
//	marketplace build                       the server-plugin packages, from the approved tags
//	marketplace index                       index.json from the manifests, signed if a key is given
//	marketplace verify index.json           the signature, with the public key
//	marketplace keygen                      a fresh signing pair
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/pacenote-sim/marketplace/internal/artifacts"
	"github.com/pacenote-sim/marketplace/internal/check"
	"github.com/pacenote-sim/marketplace/internal/index"
	"github.com/pacenote-sim/marketplace/internal/manifest"
	"github.com/pacenote-sim/marketplace/internal/policy"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usage = `usage: marketplace <command> [flags]

  validate [files...]   validate manifests (default: plugins/*.yaml)
  check <file>          check one plugin's newest approved tag, or --tag, or --dir
  build                 build the server-plugin packages into --out, with artifacts.json
  index                 write index.json (and .sig when MARKETPLACE_SIGNING_KEY is set)
  verify <index>        verify index.json against --pub or MARKETPLACE_PUBLIC_KEY
  keygen                print a new signing key pair
`

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "validate":
		err = validate(args[1:], stdout)
	case "check":
		err = checkCmd(ctx, args[1:], stdout)
	case "build":
		err = buildCmd(ctx, args[1:], stdout)
	case "index":
		err = indexCmd(args[1:], stdout)
	case "verify":
		err = verifyCmd(args[1:], stdout)
	case "keygen":
		err = keygen(stdout)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n%s", args[0], usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		if errors.Is(err, errFailed) {
			return 1
		}
		return 2
	}
	return 0
}

// errFailed is a check or validation that ran and found problems, as opposed
// to a tool that could not run.
var errFailed = errors.New("failed")

func validate(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors are returned, not printed twice
	pol := fs.String("policy", "policy", "the policy directory")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("flags: %w", err)
	}
	p, err := policy.Load(*pol)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	files := fs.Args()
	var (
		ms   []*manifest.Manifest
		errs []error
	)
	if len(files) == 0 {
		ms, err = manifest.LoadDir("plugins")
		if err != nil {
			errs = append(errs, err)
		}
	} else {
		for _, f := range files {
			m, lerr := manifest.Load(f)
			if lerr != nil {
				errs = append(errs, lerr)
				continue
			}
			if verr := m.Validate(); verr != nil {
				errs = append(errs, fmt.Errorf("%s: %w", f, verr))
			}
			ms = append(ms, m)
		}
		errs = append(errs, manifest.Collisions(ms)...)
	}
	for _, m := range ms {
		for i, v := range m.Versions {
			if !p.Supports(m.Kind, v.InterfaceVersion) {
				errs = append(errs, fmt.Errorf("%s: versions[%d] %s: interface version %d is not one the current host accepts", m.Name, i, v.Tag, v.InterfaceVersion))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w:\n%w", errFailed, errors.Join(errs...))
	}
	fmt.Fprintf(stdout, "%d manifests valid\n", len(ms))
	return nil
}

func checkCmd(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors are returned, not printed twice
	pol := fs.String("policy", "policy", "the policy directory")
	tag := fs.String("tag", "", "the tag to check (default: the newest approved version)")
	dir := fs.String("dir", "", "a local checkout to check instead of fetching the tag")
	vuln := fs.Bool("vuln", false, "also run govulncheck")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("flags: %w", err)
	}
	if fs.NArg() != 1 {
		return errors.New("check: one manifest file")
	}
	p, err := policy.Load(*pol)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	m, err := manifest.Load(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	if verr := m.Validate(); verr != nil {
		return fmt.Errorf("%w: %w", errFailed, verr)
	}
	v := m.Latest()
	if *tag != "" {
		v = nil
		for i := range m.Versions {
			if m.Versions[i].Tag == *tag {
				v = &m.Versions[i]
			}
		}
	}
	if v == nil {
		return fmt.Errorf("%s: no such approved version", m.Name)
	}
	runner := check.Exec{}
	src := *dir
	if src == "" {
		fmt.Fprintf(stdout, "fetching %s@%s\n", m.Module, v.Tag)
		src, err = check.Fetch(ctx, runner, m.Module, v.Tag)
		if err != nil {
			return fmt.Errorf("fetch: %w", err)
		}
	}
	fmt.Fprintf(stdout, "checking %s %s in %s\n\n", m.Name, v.Tag, src)
	report, err := check.Run(ctx, check.Options{Manifest: m, Version: v, Dir: src, Policy: p, Runner: runner, Vuln: *vuln})
	if err != nil {
		return fmt.Errorf("check could not run: %w", err)
	}
	for _, f := range report.Findings {
		fmt.Fprintln(stdout, f)
	}
	if report.Failed() {
		return fmt.Errorf("\n%s %s: %w", m.Name, v.Tag, errFailed)
	}
	fmt.Fprintf(stdout, "\n%s %s: every check passed\n", m.Name, v.Tag)
	return nil
}

func buildCmd(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors are returned, not printed twice
	pol := fs.String("policy", "policy", "the policy directory")
	plugins := fs.String("plugins", "plugins", "the manifests directory")
	out := fs.String("out", "dist", "where the packages and artifacts.json go")
	base := fs.String("base-url", "", "where the packages will be downloadable from: <base-url>/<name>-<tag>/<file>")
	only := fs.String("only", "", "build one plugin by name")
	dir := fs.String("dir", "", "a local checkout to build from, with --only, instead of fetching the tag")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("flags: %w", err)
	}
	if *base == "" {
		return errors.New("build: --base-url is required")
	}
	if *dir != "" && *only == "" {
		return errors.New("build: --dir needs --only")
	}
	p, err := policy.Load(*pol)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	ms, err := manifest.LoadDir(*plugins)
	if err != nil {
		return fmt.Errorf("%w: %w", errFailed, err)
	}
	runner := check.Exec{}
	source := func(ctx context.Context, module, tag string) (string, error) {
		if *dir != "" {
			return *dir, nil
		}
		fmt.Fprintf(stdout, "fetching %s@%s\n", module, tag)
		return check.Fetch(ctx, runner, module, tag)
	}
	recs, err := artifacts.Build(ctx, artifacts.Options{
		Manifests: ms, Policy: p, Runner: runner, Source: source, OutDir: *out, BaseURL: *base, Only: *only,
	})
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}
	for _, r := range recs {
		fmt.Fprintf(stdout, "%s  %s/%s\n", r.SHA256[:12], r.Name+"-"+r.Tag, r.File)
	}
	fmt.Fprintf(stdout, "%d packages in %s\n", len(recs), *out)
	return nil
}

func indexCmd(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("index", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors are returned, not printed twice
	plugins := fs.String("plugins", "plugins", "the manifests directory")
	out := fs.String("out", "index.json", "where to write the index; the signature goes beside it as .sig")
	arts := fs.String("artifacts", "", "artifacts.json from build, so the index carries downloads")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("flags: %w", err)
	}
	ms, err := manifest.LoadDir(*plugins)
	if err != nil {
		return fmt.Errorf("%w: %w", errFailed, err)
	}
	var downloads map[index.ArtifactKey][]index.Artifact
	if *arts != "" {
		downloads, err = artifacts.Load(*arts)
		if err != nil {
			return fmt.Errorf("artifacts: %w", err)
		}
	}
	data, err := index.Build(ms, downloads, time.Now()).Marshal()
	if err != nil {
		return fmt.Errorf("index: %w", err)
	}
	//nolint:gosec // index.json is published; it is meant to be world-readable
	if werr := os.WriteFile(*out, data, 0o644); werr != nil {
		return fmt.Errorf("write %s: %w", *out, werr)
	}
	fmt.Fprintf(stdout, "%s: %d plugins\n", *out, len(ms))
	key := os.Getenv("MARKETPLACE_SIGNING_KEY")
	if key == "" {
		fmt.Fprintln(stdout, "MARKETPLACE_SIGNING_KEY not set; index not signed")
		return nil
	}
	sig, err := index.Sign(data, key)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	//nolint:gosec // the signature is published beside the index
	if err := os.WriteFile(*out+".sig", []byte(sig+"\n"), 0o644); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}
	fmt.Fprintf(stdout, "%s.sig written\n", *out)
	return nil
}

func verifyCmd(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors are returned, not printed twice
	pub := fs.String("pub", os.Getenv("MARKETPLACE_PUBLIC_KEY"), "the public key, base64")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("flags: %w", err)
	}
	if fs.NArg() != 1 {
		return errors.New("verify: one index file")
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("read index: %w", err)
	}
	sig, err := os.ReadFile(fs.Arg(0) + ".sig")
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	if _, err := index.Parse(data); err != nil {
		return fmt.Errorf("%w: %w", errFailed, err)
	}
	if err := index.Verify(data, string(trimNL(sig)), *pub); err != nil {
		return fmt.Errorf("%w: %w", errFailed, err)
	}
	fmt.Fprintf(stdout, "%s: signature verifies\n", filepath.Base(fs.Arg(0)))
	return nil
}

func keygen(stdout io.Writer) error {
	k, err := index.GenerateKeys()
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}
	fmt.Fprintf(stdout, "MARKETPLACE_PUBLIC_KEY=%s\nMARKETPLACE_SIGNING_KEY=%s\n", k.Public, k.Private)
	return nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
