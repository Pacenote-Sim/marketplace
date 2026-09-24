# Publishing a plugin

A plugin is listed when a pull request adding its manifest is merged. One flow for every plugin:
server or client, open or closed, free or paid. Approval means a person read the code and the
automated checks passed on the exact tag that is listed.

## Before you open the pull request

1. **Tag a release** in your repository, `vX.Y.Z`, and make sure the module builds from that tag
   with `CGO_ENABLED=0` on Linux, macOS and Windows. A plugin that needs cgo is not eligible.
2. **Read the policy.** [policy/imports.yaml](policy/imports.yaml) says what a client plugin may
   import; [policy/platforms.yaml](policy/platforms.yaml) says what it must build for;
   [policy/interfaces.yaml](policy/interfaces.yaml) says which contract versions are accepted.
3. **Run the checks yourself.** Clone this repository, write your manifest (below), and run
   `go run ./cmd/marketplace check --dir /path/to/your/checkout plugins/<name>.yaml`. Fix what it
   reports. A pull request that fails the checks is not read.
4. **If the repository is private**, add the GitHub user `pacenote-review` as a read-only
   collaborator. The checks and the reviewer read the code through that account, and Pacenote's
   build service builds it with the same access. Nothing else about the process differs.
5. **Turn on two-factor authentication** on the GitHub account that owns the repository. A
   pull request from an account without it is closed.

## The manifest

One file, `plugins/<name>.yaml`. The name is your plugin's name as its own manifest declares it,
prefixed `client-` for a source or a companion, because the marketplace lists the two halves of a
plugin under two names.

```yaml
name: client-example
kind: companion            # server | source | companion
title: Example
summary: One sentence an operator reads in the list. Ten to a hundred and sixty characters.
author: Your name or organisation
contact: you@example.com   # or an https URL
repository: https://github.com/you/client-example
module: github.com/you/client-example
licence: MIT               # an SPDX identifier
visibility: public         # private: pacenote-review has read access, Pacenote builds it
pricing: free              # paid: activation and money are yours; the marketplace only says so
website: https://example.com/plugin      # optional
calls: []                  # every host the plugin dials, bare lower-case names; [] means none
companion_of: example      # a companion names its server plugin; a source names its simulator
                           # under simulators: [iracing] instead
dependencies:              # every module outside the standard library and the contracts
  - value: github.com/some/module
    reason: Why it is needed.
imports_allow:             # standard packages the policy does not allow by default
  - value: os/exec
    reason: Why it is needed.
not_hosts:                 # string literals the host scan flagged that are not dialled
  - docs.example.com
versions:
  - tag: v0.1.0
    approved: 2026-09-24   # the reviewer fills these two in
    reviewer: name
    interface_version: 1   # the contract version the tag was built against
    status: approved
    notes: What is new.
```

Leave `approved` and `reviewer` as they are in the example; the reviewer sets them when merging.

## What the checks do

On the tag you list, in this order:

| Check | Fails when |
|---|---|
| licence | there is no `LICENSE` file at the module root |
| manifest | your `plugin.json` or `client-plugin.json` disagrees with the marketplace manifest: name, kind, hosts, interface version; or the interface version is one no current host accepts |
| imports | a client plugin imports a standard package outside the policy without an `imports_allow` reason, or a module outside the contracts without a `dependencies` reason |
| symbols | a client plugin uses something that dials, listens or runs a process: `http.Client`, `net.Dial`, `exec.Command` and the rest of the list in the policy |
| hosts | a string literal names a host that is not in `calls` or `not_hosts` |
| build | the module does not build with `CGO_ENABLED=0` for a platform in the policy, `go vet` complains, or `go mod tidy` would change something |
| reproducible | a server plugin's binary differs between two builds |
| vuln | `govulncheck` reports a vulnerability that is reached |

The host check is a heuristic: it reports every string literal that looks like a host name, which
is anything with three or more dot-separated labels, or two labels ending in a common top-level
domain. Request kinds like `voice.speak` and file names are not reported. When it flags a literal
that is a link on your page and not a host you dial, list it under `not_hosts`; the reviewer sees
both the literal and your reason.

## After the checks pass

A reviewer reads the code against [REVIEW.md](REVIEW.md) and writes a paragraph in the pull request.
Merge is approval: the index is regenerated, signed and published, servers see the entry within the
hour, and the site on its next deploy.

## Updating

The same pull request for a new tag: add a version to `versions`. The review surface is the diff
since the last approved tag. Every version is reviewed.

## Withdrawing

Set a version's `status` to `withdrawn` and say why in `notes`. Servers warn about installed
copies, refuse new installs and builds with it, and the build service stops signing exes that
contain it. A withdrawn version stays in the index, so the record of what was approved when stays.

## What Pacenote does not do

It does not collect money, check licences at build time or take a cut. A paid plugin handles its
own registration and activation, by key, by URL or however it likes; the manifest only says
`pricing: paid` so an operator knows before installing.
