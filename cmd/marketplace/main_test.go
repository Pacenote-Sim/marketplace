package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	plugins = "../../plugins"
	pol     = "../../policy"
)

func exec(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestUsage(t *testing.T) {
	t.Parallel()
	code, _, errs := exec(t)
	assert.Equal(t, 2, code)
	assert.Contains(t, errs, "usage")
	code, out, _ := exec(t, "help")
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "validate")
	code, _, errs = exec(t, "frobnicate")
	assert.Equal(t, 2, code)
	assert.Contains(t, errs, `unknown command "frobnicate"`)
}

func TestValidate(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob(filepath.Join(plugins, "*.yaml"))
	require.NoError(t, err)
	code, out, errs := exec(t, append([]string{"validate", "--policy", pol}, files...)...)
	assert.Equal(t, 0, code, errs)
	assert.Contains(t, out, "7 manifests valid")

	bad := filepath.Join(t.TempDir(), "client-x.yaml")
	require.NoError(t, os.WriteFile(bad, []byte("name: client-x\nkind: companion\n"), 0o600))
	code, _, errs = exec(t, "validate", "--policy", pol, bad)
	assert.Equal(t, 1, code)
	assert.Contains(t, errs, "failed")
	assert.Contains(t, errs, "companion_of")

	code, _, errs = exec(t, "validate", "--policy", pol, filepath.Join(t.TempDir(), "missing.yaml"))
	assert.Equal(t, 1, code)
	assert.Contains(t, errs, "missing.yaml")

	code, _, _ = exec(t, "validate", "--policy", t.TempDir())
	assert.Equal(t, 2, code, "no policy is a tool error, not a validation failure")

	code, _, _ = exec(t, "validate", "--bogus")
	assert.Equal(t, 2, code)
}

func TestValidate_UnsupportedInterface(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m := `name: client-x
kind: companion
title: X
summary: A companion built against a contract nobody accepts.
author: t
contact: t@example.com
repository: https://github.com/x/y
module: github.com/x/y
licence: MIT
visibility: public
pricing: free
calls: []
companion_of: x
versions:
  - {tag: v0.1.0, approved: 2026-09-24, reviewer: r, interface_version: 9, status: approved}
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "client-x.yaml"), []byte(m), 0o600))
	code, _, errs := exec(t, "validate", "--policy", pol, filepath.Join(dir, "client-x.yaml"))
	assert.Equal(t, 1, code)
	assert.Contains(t, errs, "interface version 9 is not one the current host accepts")
}

func TestCheck_LocalDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m := `name: client-demo
kind: companion
title: Demo
summary: The good companion fixture, checked through the command.
author: t
contact: t@example.com
repository: https://github.com/x/y
module: example.test/companion-ok
licence: MIT
visibility: public
pricing: free
calls: []
companion_of: demo
versions:
  - {tag: v0.1.0, approved: 2026-09-24, reviewer: r, interface_version: 1, status: approved}
  - {tag: v0.2.0, approved: 2026-09-25, reviewer: r, interface_version: 1, status: withdrawn, notes: test}
`
	path := filepath.Join(dir, "client-demo.yaml")
	require.NoError(t, os.WriteFile(path, []byte(m), 0o600))
	fixture, err := filepath.Abs("../../internal/check/testdata/companion-ok")
	require.NoError(t, err)

	code, out, errs := exec(t, "check", "--policy", pol, "--dir", fixture, path)
	assert.Equal(t, 0, code, errs)
	assert.Contains(t, out, "checking client-demo v0.1.0", "the newest approved tag, not the withdrawn one")
	assert.Contains(t, out, "every check passed")

	code, out, _ = exec(t, "check", "--policy", pol, "--dir", fixture, "--tag", "v0.1.0", path)
	assert.Equal(t, 0, code)
	assert.Contains(t, out, "v0.1.0")

	code, _, errs = exec(t, "check", "--policy", pol, "--dir", fixture, "--tag", "v9.9.9", path)
	assert.Equal(t, 2, code)
	assert.Contains(t, errs, "no such approved version")

	code, _, errs = exec(t, "check", "--policy", pol, path, path)
	assert.Equal(t, 2, code)
	assert.Contains(t, errs, "one manifest file")

	code, _, _ = exec(t, "check", "--policy", t.TempDir(), path)
	assert.Equal(t, 2, code)

	code, _, _ = exec(t, "check", "--policy", pol, filepath.Join(dir, "missing.yaml"))
	assert.Equal(t, 2, code)

	code, _, _ = exec(t, "check", "--nope")
	assert.Equal(t, 2, code)
}

func TestCheck_Failing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m := `name: client-demo
kind: companion
title: Demo
summary: The bad companion fixture, checked through the command.
author: t
contact: t@example.com
repository: https://github.com/x/y
module: example.test/companion-bad
licence: MIT
visibility: public
pricing: free
calls: []
companion_of: demo
versions:
  - {tag: v0.1.0, approved: 2026-09-24, reviewer: r, interface_version: 1, status: approved}
`
	path := filepath.Join(dir, "client-demo.yaml")
	require.NoError(t, os.WriteFile(path, []byte(m), 0o600))
	fixture, err := filepath.Abs("../../internal/check/testdata/companion-bad")
	require.NoError(t, err)
	code, out, errs := exec(t, "check", "--policy", pol, "--dir", fixture, path)
	assert.Equal(t, 1, code)
	assert.Contains(t, out, "fail hosts")
	assert.Contains(t, errs, "failed")

	invalid := filepath.Join(dir, "invalid.yaml")
	require.NoError(t, os.WriteFile(invalid, []byte("name: client-demo\nkind: companion\n"), 0o600))
	code, _, errs = exec(t, "check", "--policy", pol, "--dir", fixture, invalid)
	assert.Equal(t, 1, code)
	assert.Contains(t, errs, "companion_of")
}

func TestCheck_FetchFails(t *testing.T) {
	dir := t.TempDir()
	m := `name: client-demo
kind: companion
title: Demo
summary: A module that does not exist on any proxy.
author: t
contact: t@example.com
repository: https://github.com/x/y
module: invalid.test/does-not-exist
licence: MIT
visibility: public
pricing: free
calls: []
companion_of: demo
versions:
  - {tag: v0.1.0, approved: 2026-09-24, reviewer: r, interface_version: 1, status: approved}
`
	path := filepath.Join(dir, "client-demo.yaml")
	require.NoError(t, os.WriteFile(path, []byte(m), 0o600))
	t.Setenv("GOPROXY", "off")
	code, _, errs := exec(t, "check", "--policy", pol, path)
	assert.Equal(t, 2, code)
	assert.Contains(t, errs, "fetch")
}

func TestIndexVerifyKeygen(t *testing.T) {
	code, out, _ := exec(t, "keygen")
	require.Equal(t, 0, code)
	pub, priv := parseKeys(t, out)

	dir := t.TempDir()
	idx := filepath.Join(dir, "index.json")

	t.Setenv("MARKETPLACE_SIGNING_KEY", "")
	code, out, errs := exec(t, "index", "--plugins", plugins, "--out", idx)
	require.Equal(t, 0, code, errs)
	assert.Contains(t, out, "7 plugins")
	assert.Contains(t, out, "not signed")
	_, err := os.Stat(idx + ".sig")
	require.True(t, os.IsNotExist(err))

	t.Setenv("MARKETPLACE_SIGNING_KEY", priv)
	code, out, errs = exec(t, "index", "--plugins", plugins, "--out", idx)
	require.Equal(t, 0, code, errs)
	assert.Contains(t, out, ".sig written")

	code, out, errs = exec(t, "verify", "--pub", pub, idx)
	assert.Equal(t, 0, code, errs)
	assert.Contains(t, out, "signature verifies")

	t.Setenv("MARKETPLACE_PUBLIC_KEY", pub)
	code, _, _ = exec(t, "verify", idx)
	assert.Equal(t, 0, code, "the public key may come from the environment")

	code, out, _ = exec(t, "keygen")
	require.Equal(t, 0, code)
	otherPub, _ := parseKeys(t, out)
	code, _, errs = exec(t, "verify", "--pub", otherPub, idx)
	assert.Equal(t, 1, code)
	assert.Contains(t, errs, "does not verify")
	code, _, errs = exec(t, "verify", "--pub", "not-a-key", idx)
	assert.Equal(t, 1, code)
	assert.Contains(t, errs, "public key")

	data, err := os.ReadFile(idx)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(idx, bytes.Replace(data, []byte("voice"), []byte("noise"), 1), 0o600))
	code, _, _ = exec(t, "verify", "--pub", pub, idx)
	assert.Equal(t, 1, code, "a changed byte fails")

	require.NoError(t, os.WriteFile(idx, []byte("{"), 0o600))
	code, _, _ = exec(t, "verify", "--pub", pub, idx)
	assert.Equal(t, 1, code, "an unreadable index fails")

	code, _, _ = exec(t, "verify", "--pub", pub, filepath.Join(dir, "missing.json"))
	assert.Equal(t, 2, code)
	require.NoError(t, os.Remove(idx+".sig"))
	code, _, _ = exec(t, "verify", "--pub", pub, idx)
	assert.Equal(t, 2, code, "a missing signature is a tool error")

	code, _, _ = exec(t, "verify")
	assert.Equal(t, 2, code)
	code, _, _ = exec(t, "verify", "--nope")
	assert.Equal(t, 2, code)

	t.Setenv("MARKETPLACE_SIGNING_KEY", "not a key")
	code, _, errs = exec(t, "index", "--plugins", plugins, "--out", idx)
	assert.Equal(t, 2, code)
	assert.Contains(t, errs, "private key")

	code, _, _ = exec(t, "index", "--plugins", dir, "--out", filepath.Join(dir, "no", "such", "dir", "index.json"))
	assert.Equal(t, 2, code, "an unwritable output is a tool error")

	broken := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(broken, "x.yaml"), []byte("name: ["), 0o600))
	code, _, _ = exec(t, "index", "--plugins", broken, "--out", idx)
	assert.Equal(t, 1, code, "a broken manifest fails the index")

	code, _, _ = exec(t, "index", "--nope")
	assert.Equal(t, 2, code)
}

func parseKeys(t *testing.T, out string) (pub, priv string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		k, v, _ := strings.Cut(line, "=")
		switch k {
		case "MARKETPLACE_PUBLIC_KEY":
			pub = v
		case "MARKETPLACE_SIGNING_KEY":
			priv = v
		}
	}
	require.NotEmpty(t, pub)
	require.NotEmpty(t, priv)
	return pub, priv
}
