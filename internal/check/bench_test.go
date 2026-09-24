package check_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/pacenote-sim/marketplace/internal/check"
	"github.com/pacenote-sim/marketplace/internal/policy"
)

// BenchmarkRun_Companion is what one full check costs on a small module. It is
// dominated by the toolchain, which is the point: the checks themselves
// should add nothing anyone notices.
func BenchmarkRun_Companion(b *testing.B) {
	p, err := policy.Load(filepath.Join("..", "..", "policy"))
	if err != nil {
		b.Fatal(err)
	}
	dir, _ := filepath.Abs(filepath.Join("testdata", "companion-ok"))
	m, v := companion("client-demo", "example.test/companion-ok", "demo", []string{})
	for b.Loop() {
		if _, err := check.Run(context.Background(), check.Options{Manifest: m, Version: v, Dir: dir, Policy: p, Runner: check.Exec{}}); err != nil {
			b.Fatal(err)
		}
	}
}
