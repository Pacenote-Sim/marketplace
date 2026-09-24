package check

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func sortStrings(s []string) { sort.Strings(s) }

func readFile(name string) ([]byte, error) {
	data, err := os.ReadFile(name) //nolint:gosec // a file at the root of the module under review
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(name), err)
	}
	return data, nil
}

// checkBuild compiles the module for every platform the policy names, with
// CGO_ENABLED=0, then vets it and confirms go.mod and go.sum are tidy. A plugin
// that needs cgo fails here and is not eligible; that is the rule, not a gap.
func checkBuild(ctx context.Context, r *Report, o Options) {
	for _, pl := range o.Policy.PlatformsFor(o.Manifest.Kind) {
		env := []string{"CGO_ENABLED=0", "GOOS=" + pl.OS, "GOARCH=" + pl.Arch}
		if _, err := o.Runner.Run(ctx, o.Dir, env, "go", "build", "./..."); err != nil {
			r.add("build", Fail, "%s: %s", pl, firstLines(err, 6))
			continue
		}
		r.add("build", Info, "%s builds with CGO_ENABLED=0", pl)
	}
	if _, err := o.Runner.Run(ctx, o.Dir, nil, "go", "vet", "./..."); err != nil {
		r.add("vet", Fail, "%s", firstLines(err, 6))
	} else {
		r.add("vet", Info, "go vet is clean")
	}
	if _, err := o.Runner.Run(ctx, o.Dir, nil, "go", "mod", "tidy", "-diff"); err != nil {
		r.add("tidy", Fail, "go.mod or go.sum is not tidy: %s", firstLines(err, 6))
	} else {
		r.add("tidy", Info, "go mod tidy is a no-op")
	}
}

// checkReproducible builds the server plugin's binary twice and compares the
// bytes. What the marketplace serves must be what any reviewer can rebuild.
func checkReproducible(ctx context.Context, r *Report, o Options) {
	p, _, err := readPluginJSON(o)
	if err != nil || p.Binary == "" {
		r.add("reproducible", Fail, "cannot tell which binary to build: plugin.json has no binary")
		return
	}
	main := "./cmd/" + p.Binary
	if st, serr := os.Stat(filepath.Join(o.Dir, "cmd", p.Binary)); serr != nil || !st.IsDir() {
		r.add("reproducible", Fail, "plugin.json names binary %q but there is no %s package", p.Binary, main)
		return
	}
	tmp, err := os.MkdirTemp("", "marketplace-build-")
	if err != nil {
		r.add("reproducible", Fail, "temp dir: %v", err)
		return
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	sums := make([]string, 0, 2)
	for i := range 2 {
		out := filepath.Join(tmp, fmt.Sprintf("bin%d", i))
		env := []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOFLAGS=-trimpath -buildvcs=false"}
		if _, berr := o.Runner.Run(ctx, o.Dir, env, "go", "build", "-ldflags=-s -w", "-o", out, main); berr != nil {
			r.add("reproducible", Fail, "build %d: %s", i+1, firstLines(berr, 6))
			return
		}
		sum, herr := fileSHA256(out)
		if herr != nil {
			r.add("reproducible", Fail, "%v", herr)
			return
		}
		sums = append(sums, sum)
	}
	if sums[0] != sums[1] {
		r.add("reproducible", Fail, "two builds of %s differ: %s vs %s", main, sums[0][:12], sums[1][:12])
		return
	}
	r.add("reproducible", Info, "%s builds the same bytes twice (sha256 %s)", main, sums[0][:12])
}

// checkVuln runs govulncheck when it is installed.
func checkVuln(ctx context.Context, r *Report, o Options) {
	if _, err := o.Runner.Run(ctx, o.Dir, nil, "govulncheck", "./..."); err != nil {
		var exit interface{ ExitCode() int }
		if errors.As(err, &exit) && exit.ExitCode() == 3 {
			r.add("vuln", Fail, "%s", firstLines(err, 12))
			return
		}
		r.add("vuln", Warn, "govulncheck could not run: %s", firstLines(err, 3))
		return
	}
	r.add("vuln", Info, "govulncheck finds nothing")
}

func fileSHA256(name string) (string, error) {
	f, err := os.Open(name) //nolint:gosec // a binary this check just built in its own temp dir
	if err != nil {
		return "", fmt.Errorf("open %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", name, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func firstLines(err error, n int) string {
	lines := strings.Split(strings.TrimSpace(err.Error()), "\n")
	if len(lines) > n {
		lines = append(lines[:n], "…")
	}
	return strings.Join(lines, "\n     ")
}
