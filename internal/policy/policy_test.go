package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pacenote-sim/marketplace/internal/manifest"
	"github.com/pacenote-sim/marketplace/internal/policy"
)

// TestLoad_Real loads the policy the marketplace actually applies.
func TestLoad_Real(t *testing.T) {
	t.Parallel()
	p, err := policy.Load(filepath.Join("..", "..", "policy"))
	require.NoError(t, err)

	assert.True(t, p.Supports(manifest.KindServer, 3))
	assert.False(t, p.Supports(manifest.KindServer, 1))
	assert.True(t, p.Supports(manifest.KindCompanion, 1))
	assert.False(t, p.Supports(manifest.KindSource, 3))

	assert.Len(t, p.PlatformsFor(manifest.KindServer), 5)
	assert.Len(t, p.PlatformsFor(manifest.KindSource), 3)
	assert.Equal(t, "windows/amd64", p.PlatformsFor(manifest.KindCompanion)[0].String())

	assert.Nil(t, p.ImportsFor(manifest.KindServer), "a server plugin has no import policy")
	assert.NotEmpty(t, p.ImportsFor(manifest.KindCompanion).Std)
	assert.NotEmpty(t, p.ImportsFor(manifest.KindSource).DenySymbols["net/http"])
	assert.Contains(t, p.ImportsFor(manifest.KindSource).Std, "os", "a source reads the simulator")
	assert.NotContains(t, p.ImportsFor(manifest.KindCompanion).Std, "os", "a companion has no business on the disk")

	assert.True(t, p.IsContract("github.com/pacenote-sim/clientplugin"))
	assert.False(t, p.IsContract("github.com/pacenote-sim/client"))
	assert.Contains(t, p.KnownHosts, "www.pacenote.tech")
}

func TestLoad_Errors(t *testing.T) {
	t.Parallel()
	_, err := policy.Load(t.TempDir())
	require.Error(t, err, "no files is an error: a missing policy must not mean no rules")

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "x.yaml"), []byte("interfaces: {plugin: [3]}\nnonsense: 1\n"), 0o600))
	_, err = policy.Load(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonsense")
}
