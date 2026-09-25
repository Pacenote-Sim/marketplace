# marketplace

The index of approved Pacenote plugins: one manifest per plugin, the checks a pull request runs, the
checklist a reviewer reads, and the tool that turns the merged manifests into the signed
`index.json` the server and pacenote.tech read.

- To publish a plugin, read [SUBMITTING.md](SUBMITTING.md).
- To review one, read [REVIEW.md](REVIEW.md).
- The rules the checks apply are in [policy/](policy/), in plain YAML, and change by pull request
  like anything else.

## The tool

```
go run ./cmd/marketplace validate                    # every manifest under plugins/
go run ./cmd/marketplace check plugins/voice.yaml    # fetch the newest approved tag and check it
go run ./cmd/marketplace check --dir ../voice plugins/voice.yaml   # a local checkout instead
go run ./cmd/marketplace build --base-url https://github.com/Pacenote-Sim/marketplace/releases/download
                                                     # the server-plugin packages, into dist/
go run ./cmd/marketplace index --artifacts dist/artifacts.json --modules dist/modules.json
                                                     # index.json with downloads and module hashes, signed when MARKETPLACE_SIGNING_KEY is set
```

## Where things are published

On every merge that touches a manifest, CI builds the server-plugin packages from the approved tags and
attaches them to a release on this repository named `<plugin>-<tag>`, records every approved tag's
module hash, then generates the index, signs it and publishes `index.json`, `index.json.sig` and `PUBLIC_KEY` to this repository's GitHub Pages.
pacenote.tech serves those same files under `https://www.pacenote.tech/marketplace/`, which is the
address a server is given. `PUBLIC_KEY` at the root of this repository is the key a server verifies
the index with.

`make` runs what CI runs on the tool itself. `make check-plugins` fetches and checks every listed
plugin, which needs the network and a few minutes.

## Licence

Apache-2.0, see `LICENSE`. The manifests describe plugins under their own licences.
