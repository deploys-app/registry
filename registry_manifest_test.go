package main

import (
	"encoding/json"
	"testing"
)

// Classifying a manifest body drives how its size is computed: an image index /
// manifest list (with a "manifests" array) sums its children, while an image
// manifest (with "config"/"layers") sums its blobs. Misclassifying an index as
// an image is exactly the bug that left multi-arch sizes at 0.
func TestManifestContentClassification(t *testing.T) {
	imageManifest := `{
		"schemaVersion": 2,
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": {"digest": "sha256:cfg", "size": 7},
		"layers": [
			{"digest": "sha256:l1", "size": 100},
			{"digest": "sha256:l2", "size": 200},
			{"digest": "sha256:l1", "size": 100}
		]
	}`
	imageIndex := `{
		"schemaVersion": 2,
		"mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": [
			{"digest": "sha256:amd64", "platform": {"architecture": "amd64", "os": "linux"}},
			{"digest": "sha256:arm64", "platform": {"architecture": "arm64", "os": "linux"}}
		]
	}`

	var img manifestContent
	if err := json.Unmarshal([]byte(imageManifest), &img); err != nil {
		t.Fatalf("unmarshal image: %v", err)
	}
	if len(img.Manifests) != 0 {
		t.Errorf("image manifest must not be classified as an index, got %d child manifests", len(img.Manifests))
	}
	// config + 2 distinct layers (one duplicated) → 3 unique blob digests
	blobs := dedupeDigests(append([]struct {
		Digest string `json:"digest"`
	}{img.Config}, img.Layers...), func(l struct {
		Digest string `json:"digest"`
	}) string {
		return l.Digest
	})
	if len(blobs) != 3 {
		t.Errorf("want 3 unique blob digests, got %d: %v", len(blobs), blobs)
	}

	var idx manifestContent
	if err := json.Unmarshal([]byte(imageIndex), &idx); err != nil {
		t.Fatalf("unmarshal index: %v", err)
	}
	if len(idx.Manifests) != 2 {
		t.Fatalf("image index must expose its 2 children, got %d", len(idx.Manifests))
	}
	if idx.Config.Digest != "" || len(idx.Layers) != 0 {
		t.Errorf("image index must have no config/layers, got config=%q layers=%d", idx.Config.Digest, len(idx.Layers))
	}
	children := dedupeDigests(idx.Manifests, func(c struct {
		Digest string `json:"digest"`
	}) string {
		return c.Digest
	})
	if len(children) != 2 {
		t.Errorf("want 2 child digests, got %d: %v", len(children), children)
	}
}
