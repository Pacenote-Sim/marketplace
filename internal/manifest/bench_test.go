package manifest_test

import "testing"

// BenchmarkValidate is what one manifest costs to check. It runs on every
// pull request for every manifest, so it should stay in the microseconds.
func BenchmarkValidate(b *testing.B) {
	m := good()
	b.ReportAllocs()
	for b.Loop() {
		if err := m.Validate(); err != nil {
			b.Fatal(err)
		}
	}
}
