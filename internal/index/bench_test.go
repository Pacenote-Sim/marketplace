package index_test

import (
	"testing"
	"time"

	"github.com/pacenote-sim/marketplace/internal/index"
)

// BenchmarkBuildMarshal is what publishing costs; it should stay trivial as
// the index grows to hundreds of plugins.
func BenchmarkBuildMarshal(b *testing.B) {
	ms := manifests()
	for range 200 {
		ms = append(ms, ms[0])
	}
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := index.Build(ms, nil, now).Marshal(); err != nil {
			b.Fatal(err)
		}
	}
}
