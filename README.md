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
go run ./cmd/marketplace index                       # index.json, signed when MARKETPLACE_SIGNING_KEY is set
```

`make` runs what CI runs on the tool itself. `make check-plugins` fetches and checks every listed
plugin, which needs the network and a few minutes.

## Licence

Apache-2.0, see `LICENSE`. The manifests describe plugins under their own licences.
