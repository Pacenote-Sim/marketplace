package manifest_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pacenote-sim/marketplace/internal/manifest"
)

func good() *manifest.Manifest {
	return &manifest.Manifest{
		Name: "client-demo", Kind: manifest.KindCompanion, Title: "Demo", Summary: "A companion that does one thing for the tests.",
		Author: "Test", Contact: "test@example.com", Repository: "https://github.com/example/client-demo",
		Module: "github.com/example/client-demo", Licence: "MIT", Visibility: manifest.Public, Pricing: manifest.Free,
		Calls: []string{}, CompanionOf: "demo",
		Versions: []manifest.Version{{Tag: "v0.1.0", Approved: "2026-09-24", Reviewer: "r", InterfaceVersion: 1, Status: manifest.StatusApproved}},
	}
}

func TestValidate_Good(t *testing.T) {
	t.Parallel()
	require.NoError(t, good().Validate())
	assert.Equal(t, "v0.1.0", good().Latest().Tag)
}

func TestValidate_Bad(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		mutate func(*manifest.Manifest)
		want   string
	}{
		"name upper":            {func(m *manifest.Manifest) { m.Name = "Client-Demo" }, "lower-case"},
		"name too short":        {func(m *manifest.Manifest) { m.Name = "a" }, "2 to 40"},
		"client without prefix": {func(m *manifest.Manifest) { m.Name = "demo" }, "starts with client-"},
		"server with prefix":    {func(m *manifest.Manifest) { m.Kind = manifest.KindServer; m.CompanionOf = ""; m.Name = "client-x" }, "does not start with client-"},
		"kind":                  {func(m *manifest.Manifest) { m.Kind = "thing" }, "one of server, source, companion"},
		"title":                 {func(m *manifest.Manifest) { m.Title = "" }, "title"},
		"summary short":         {func(m *manifest.Manifest) { m.Summary = "short" }, "summary"},
		"author":                {func(m *manifest.Manifest) { m.Author = "" }, "author"},
		"contact empty":         {func(m *manifest.Manifest) { m.Contact = "" }, "contact"},
		"contact bad email":     {func(m *manifest.Manifest) { m.Contact = "not an @ address" }, "not an email"},
		"contact http":          {func(m *manifest.Manifest) { m.Contact = "http://example.com" }, "https"},
		"repository":            {func(m *manifest.Manifest) { m.Repository = "git@github.com:x/y" }, "repository"},
		"module":                {func(m *manifest.Manifest) { m.Module = "not a module path" }, "module"},
		"licence":               {func(m *manifest.Manifest) { m.Licence = "" }, "licence"},
		"visibility":            {func(m *manifest.Manifest) { m.Visibility = "secret" }, "visibility"},
		"pricing":               {func(m *manifest.Manifest) { m.Pricing = "cheap" }, "pricing"},
		"website":               {func(m *manifest.Manifest) { m.Website = "ftp://x" }, "website"},
		"calls nil":             {func(m *manifest.Manifest) { m.Calls = nil }, "calls: required"},
		"calls scheme":          {func(m *manifest.Manifest) { m.Calls = []string{"https://api.example.com"} }, "bare lower-case host"},
		"calls one label":       {func(m *manifest.Manifest) { m.Calls = []string{"localhost"} }, "two labels"},
		"calls bad label":       {func(m *manifest.Manifest) { m.Calls = []string{"-bad-.example.com"} }, "not valid"},
		"not_hosts empty":       {func(m *manifest.Manifest) { m.NotHosts = []string{""} }, "not_hosts"},
		"companion no server":   {func(m *manifest.Manifest) { m.CompanionOf = "" }, "companion_of"},
		"companion bad server":  {func(m *manifest.Manifest) { m.CompanionOf = "client-demo" }, "server plugin's marketplace name"},
		"companion simulator":   {func(m *manifest.Manifest) { m.Simulators = []string{"iracing"} }, "only a source"},
		"source no simulator":   {func(m *manifest.Manifest) { m.Kind = manifest.KindSource; m.CompanionOf = "" }, "exactly the one simulator"},
		"source companion_of":   {func(m *manifest.Manifest) { m.Kind = manifest.KindSource; m.Simulators = []string{"x"} }, "no server half"},
		"server simulator": {func(m *manifest.Manifest) {
			m.Kind = manifest.KindServer
			m.Name = "demo"
			m.CompanionOf = ""
			m.Simulators = []string{"x"}
		}, "only a source"},
		"server companion_of": {func(m *manifest.Manifest) { m.Kind = manifest.KindServer; m.Name = "demo"; m.CompanionOf = "other" }, "client half"},
		"server imports_allow": {func(m *manifest.Manifest) {
			m.Kind = manifest.KindServer
			m.Name = "demo"
			m.CompanionOf = ""
			m.ImportsAllow = []manifest.Reasoned{{Value: "os", Reason: "r"}}
		}, "only client plugins"},
		"dependency path":      {func(m *manifest.Manifest) { m.Dependencies = []manifest.Reasoned{{Value: "bad path!", Reason: "r"}} }, "dependencies[0]"},
		"dependency reason":    {func(m *manifest.Manifest) { m.Dependencies = []manifest.Reasoned{{Value: "github.com/x/y"}} }, "reason is required"},
		"imports_allow reason": {func(m *manifest.Manifest) { m.ImportsAllow = []manifest.Reasoned{{Value: "os"}} }, "imports_allow[0]"},
		"no versions":          {func(m *manifest.Manifest) { m.Versions = nil }, "at least one"},
		"tag not semver":       {func(m *manifest.Manifest) { m.Versions[0].Tag = "1.0" }, "canonical semantic version"},
		"tag not canonical":    {func(m *manifest.Manifest) { m.Versions[0].Tag = "v1.0" }, "canonical semantic version"},
		"tag twice":            {func(m *manifest.Manifest) { m.Versions = append(m.Versions, m.Versions[0]) }, "listed twice"},
		"tags out of order":    {func(m *manifest.Manifest) { v := m.Versions[0]; v.Tag = "v0.0.1"; m.Versions = append(m.Versions, v) }, "oldest first"},
		"approved date":        {func(m *manifest.Manifest) { m.Versions[0].Approved = "yesterday" }, "YYYY-MM-DD"},
		"reviewer":             {func(m *manifest.Manifest) { m.Versions[0].Reviewer = "" }, "reviewer"},
		"interface version":    {func(m *manifest.Manifest) { m.Versions[0].InterfaceVersion = 0 }, "interface_version"},
		"status":               {func(m *manifest.Manifest) { m.Versions[0].Status = "maybe" }, "approved or withdrawn"},
		"withdrawn no notes":   {func(m *manifest.Manifest) { m.Versions[0].Status = manifest.StatusWithdrawn }, "says why"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := good()
			tc.mutate(m)
			err := m.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestLatest(t *testing.T) {
	t.Parallel()
	m := good()
	m.Versions = append(m.Versions, manifest.Version{Tag: "v0.2.0", Approved: "2026-09-25", Reviewer: "r", InterfaceVersion: 1, Status: manifest.StatusWithdrawn, Notes: "bad"})
	require.NoError(t, m.Validate())
	assert.Equal(t, "v0.1.0", m.Latest().Tag, "the newest approved, skipping withdrawn")
	m.Versions[0].Status = manifest.StatusWithdrawn
	m.Versions[0].Notes = "also bad"
	assert.Nil(t, m.Latest())
}

func TestCollisions(t *testing.T) {
	t.Parallel()
	a, b, c := good(), good(), good()
	b.Name = "c1ient-dem0"
	c.Name = "clientdemo"
	errs := manifest.Collisions([]*manifest.Manifest{a, b, c})
	require.Len(t, errs, 2)
	assert.Empty(t, manifest.Collisions([]*manifest.Manifest{a}))
	assert.Equal(t, "clientvoice", manifest.Normalise("c1ient-v0ice"))
}

func TestParse_UnknownField(t *testing.T) {
	t.Parallel()
	_, err := manifest.Parse([]byte("name: x\nlicense: MIT\n"))
	require.Error(t, err, "a misspelt field is an error, not silently dropped")
	assert.Contains(t, err.Error(), "license")
}

func TestLoad_Errors(t *testing.T) {
	t.Parallel()
	_, err := manifest.Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.Error(t, err)
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	require.NoError(t, os.WriteFile(bad, []byte("name: [\n"), 0o600))
	_, err = manifest.Load(bad)
	require.Error(t, err)
}

func TestLoadDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, body string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}
	write("client-demo.yaml", goodYAML("client-demo"))
	write("wrong-name.yaml", goodYAML("client-other"))
	write("broken.yaml", "name: [")
	ms, err := manifest.LoadDir(dir)
	require.Error(t, err)
	assert.Len(t, ms, 2, "every manifest that parsed is returned")
	assert.Contains(t, err.Error(), `file is named "wrong-name"`)
	assert.Contains(t, err.Error(), "broken.yaml")

	_, err = manifest.LoadDir(filepath.Join(dir, "nowhere"))
	require.NoError(t, err, "an empty directory is not an error")
}

// TestOfficialManifests reads the real plugins/ directory: the seven official
// plugins are the first thing the process is tested on.
func TestOfficialManifests(t *testing.T) {
	t.Parallel()
	ms, err := manifest.LoadDir(filepath.Join("..", "..", "plugins"))
	require.NoError(t, err)
	require.Len(t, ms, 7)
	for _, m := range ms {
		assert.NotNil(t, m.Latest(), m.Name)
	}
}

func goodYAML(name string) string {
	return strings.ReplaceAll(`name: NAME
kind: companion
title: Demo
summary: A companion that does one thing for the tests.
author: Test
contact: test@example.com
repository: https://github.com/example/NAME
module: github.com/example/NAME
licence: MIT
visibility: public
pricing: free
calls: []
companion_of: demo
versions:
  - tag: v0.1.0
    approved: 2026-09-24
    reviewer: r
    interface_version: 1
    status: approved
`, "NAME", name)
}
