// Package index builds index.json, the one file the server and the site read,
// and signs it.
//
// The index is generated from the merged manifests, so it never says anything a
// pull request did not. It carries what a server needs to act: the module and
// approved tags for a client plugin; the download and its checksum, per
// platform, for a server plugin.
package index

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/pacenote-sim/marketplace/internal/manifest"
)

// Format is bumped when a field changes meaning. A server refuses an index
// whose format it does not know rather than guessing.
const Format = 1

// Artifact is one built server-plugin binary.
type Artifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

// Version is one tag of one plugin.
type Version struct {
	Tag              string          `json:"tag"`
	Approved         string          `json:"approved"`
	InterfaceVersion int             `json:"interface_version"`
	Status           manifest.Status `json:"status"`
	Notes            string          `json:"notes,omitempty"`
	Artifacts        []Artifact      `json:"artifacts,omitempty"`
}

// Plugin is one listing.
type Plugin struct {
	Name        string              `json:"name"`
	Kind        manifest.Kind       `json:"kind"`
	Title       string              `json:"title"`
	Summary     string              `json:"summary"`
	Author      string              `json:"author"`
	Repository  string              `json:"repository"`
	Module      string              `json:"module"`
	Licence     string              `json:"licence"`
	Visibility  manifest.Visibility `json:"visibility"`
	Pricing     manifest.Pricing    `json:"pricing"`
	Website     string              `json:"website,omitempty"`
	Simulators  []string            `json:"simulators,omitempty"`
	Calls       []string            `json:"calls"`
	CompanionOf string              `json:"companion_of,omitempty"`
	Versions    []Version           `json:"versions"`
}

// Index is index.json.
type Index struct {
	Format    int       `json:"format"`
	Generated time.Time `json:"generated"`
	Plugins   []Plugin  `json:"plugins"`
}

// ArtifactKey names the build of one tag of one plugin.
type ArtifactKey struct{ Name, Tag string }

// Build turns manifests into an index. artifacts may be nil while nothing has
// been built yet; the plugin is then listed without downloads.
func Build(ms []*manifest.Manifest, artifacts map[ArtifactKey][]Artifact, now time.Time) *Index {
	idx := &Index{Format: Format, Generated: now.UTC().Truncate(time.Second), Plugins: make([]Plugin, 0, len(ms))}
	for _, m := range ms {
		p := Plugin{
			Name: m.Name, Kind: m.Kind, Title: m.Title, Summary: m.Summary, Author: m.Author,
			Repository: m.Repository, Module: m.Module, Licence: m.Licence, Visibility: m.Visibility,
			Pricing: m.Pricing, Website: m.Website, Simulators: m.Simulators, CompanionOf: m.CompanionOf,
			Calls: append([]string{}, m.Calls...), Versions: make([]Version, 0, len(m.Versions)),
		}
		for _, v := range m.Versions {
			p.Versions = append(p.Versions, Version{
				Tag: v.Tag, Approved: v.Approved, InterfaceVersion: v.InterfaceVersion,
				Status: v.Status, Notes: v.Notes, Artifacts: artifacts[ArtifactKey{m.Name, v.Tag}],
			})
		}
		idx.Plugins = append(idx.Plugins, p)
	}
	return idx
}

// Marshal renders the index as the bytes that get signed and published.
// Indented, so a diff between two publishes is readable.
func (idx *Index) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal index: %w", err)
	}
	return append(b, '\n'), nil
}

// Parse reads an index.
func Parse(data []byte) (*Index, error) {
	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("parse index: %w", err)
	}
	if idx.Format != Format {
		return nil, fmt.Errorf("index format %d, this tool knows %d", idx.Format, Format)
	}
	return &idx, nil
}

// Keys are the signing pair, base64 for the environment and the server's
// configuration.
type Keys struct{ Public, Private string }

// GenerateKeys makes a fresh ed25519 pair.
func GenerateKeys() (Keys, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Keys{}, fmt.Errorf("generate key: %w", err)
	}
	return Keys{
		Public:  base64.StdEncoding.EncodeToString(pub),
		Private: base64.StdEncoding.EncodeToString(priv),
	}, nil
}

// Sign returns the detached signature of data, base64.
func Sign(data []byte, privateKey string) (string, error) {
	priv, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("private key: 64 bytes of base64 from keygen")
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(priv), data)), nil
}

// ErrSignature is returned when the signature does not match.
var ErrSignature = errors.New("index signature does not verify")

// Verify checks a detached signature against the public key.
func Verify(data []byte, signature, publicKey string) error {
	pub, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("public key: 32 bytes of base64 from keygen")
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
		return ErrSignature
	}
	return nil
}
