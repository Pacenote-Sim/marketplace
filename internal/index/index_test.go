package index_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pacenote-sim/marketplace/internal/index"
	"github.com/pacenote-sim/marketplace/internal/manifest"
)

func manifests() []*manifest.Manifest {
	return []*manifest.Manifest{{
		Name: "demo", Kind: manifest.KindServer, Title: "Demo", Summary: "A server plugin for the tests.",
		Author: "Test", Repository: "https://github.com/example/demo", Module: "github.com/example/demo",
		Licence: "MIT", Visibility: manifest.Public, Pricing: manifest.Paid, Calls: []string{"api.example.com"},
		Versions: []manifest.Version{
			{Tag: "v0.1.0", Approved: "2026-09-01", Reviewer: "r", InterfaceVersion: 3, Status: manifest.StatusWithdrawn, Notes: "leaked"},
			{Tag: "v0.2.0", Approved: "2026-09-24", Reviewer: "r", InterfaceVersion: 3, Status: manifest.StatusApproved},
		},
	}}
}

func TestBuild_RoundTrip(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 24, 12, 0, 0, 500, time.FixedZone("x", 3600))
	arts := map[index.ArtifactKey][]index.Artifact{
		{Name: "demo", Tag: "v0.2.0"}: {{OS: "linux", Arch: "amd64", URL: "https://example.com/demo.zip", SHA256: "ab"}},
	}
	hashes := map[index.ArtifactKey]string{{Name: "demo", Tag: "v0.2.0"}: "h1:abc"}
	idx := index.Build(manifests(), arts, hashes, now)
	require.Len(t, idx.Plugins, 1)
	p := idx.Plugins[0]
	assert.Equal(t, index.Format, idx.Format)
	assert.Equal(t, time.UTC, idx.Generated.Location(), "generated is UTC to the second")
	assert.Equal(t, 0, idx.Generated.Nanosecond())
	assert.Equal(t, manifest.Paid, p.Pricing)
	assert.Nil(t, p.Versions[0].Artifacts, "no artifacts for the withdrawn tag")
	assert.Equal(t, manifest.StatusWithdrawn, p.Versions[0].Status)
	assert.Len(t, p.Versions[1].Artifacts, 1)
	assert.Equal(t, "h1:abc", p.Versions[1].ModuleHash)
	assert.Empty(t, p.Versions[0].ModuleHash)

	data, err := idx.Marshal()
	require.NoError(t, err)
	again, err := index.Parse(data)
	require.NoError(t, err)
	assert.Equal(t, idx, again)

	data2, err := index.Build(manifests(), arts, hashes, now).Marshal()
	require.NoError(t, err)
	assert.Equal(t, data, data2, "the same manifests give the same bytes")
}

func TestParse_Errors(t *testing.T) {
	t.Parallel()
	_, err := index.Parse([]byte("{"))
	require.Error(t, err)
	_, err = index.Parse([]byte(`{"format": 99, "plugins": []}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "format 99")
}

func TestSignVerify(t *testing.T) {
	t.Parallel()
	keys, err := index.GenerateKeys()
	require.NoError(t, err)
	data, err := index.Build(manifests(), nil, nil, time.Now()).Marshal()
	require.NoError(t, err)

	sig, err := index.Sign(data, keys.Private)
	require.NoError(t, err)
	require.NoError(t, index.Verify(data, sig, keys.Public))

	tampered := append([]byte{}, data...)
	tampered[len(tampered)/2] ^= 1
	require.ErrorIs(t, index.Verify(tampered, sig, keys.Public), index.ErrSignature)

	other, err := index.GenerateKeys()
	require.NoError(t, err)
	require.ErrorIs(t, index.Verify(data, sig, other.Public), index.ErrSignature)

	// Padding lost in a copy, or a newline gained, is still the same key.
	require.NoError(t, index.Verify(data, sig, strings.TrimRight(keys.Public, "=")+"\n"))
	sig2, err := index.Sign(data, " "+strings.TrimRight(keys.Private, "=")+"\n")
	require.NoError(t, err)
	require.NoError(t, index.Verify(data, sig2, keys.Public))

	_, err = index.Sign(data, "not a key")
	require.Error(t, err)
	require.Error(t, index.Verify(data, sig, "not a key"))
	require.Error(t, index.Verify(data, "not base64!", keys.Public))
}
