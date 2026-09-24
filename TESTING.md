# Testing the tool

`make` runs what CI runs, in order: format, build, vet, lint, the suite with the race detector and
shuffled order, coverage over 90 % in every package, every benchmark once, `go mod tidy` a no-op,
and the manifests under `plugins/` validated against the policy.

```
make                # everything, in order
make test           # the suite alone
make cover          # the suite with the coverage floor
make check-plugins  # fetch and check every listed plugin; network, minutes
```

## What the suite asserts

| Package | |
|---|---|
| `internal/manifest` | a manifest is refused for every way it can be wrong, and accepted when right; the seven official manifests parse; look-alike names collide |
| `internal/policy` | the policy files in `policy/` load, and answer for each kind |
| `internal/index` | an index is built deterministically from manifests, round-trips through JSON, and a signature verifies with the right key and fails with the wrong one or a changed byte |
| `internal/check` | against fixture modules under `testdata/`: a good companion passes every check; a bad one is caught on the licence, the imports, the denied symbols and the undeclared host; a server plugin builds the same bytes twice; the runner runs real commands |

The checks run the real Go toolchain on the fixtures, offline: the fixtures import nothing outside
the standard library.
