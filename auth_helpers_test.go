package main

import (
	"net/http"
	"testing"
)

// TestExtractProject pins the project-scoping parser: it returns the first path
// segment after /v2/ (the project namespace the request's permissions are
// checked against), and "" when there is no namespace+repo to scope to.
func TestExtractProject(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/v2/acme/web/manifests/latest", "acme"},
		{"/v2/acme/web/blobs/sha256:abc", "acme"},
		{"/v2/acme/web/tags/list", "acme"},
		{"/v2/acme/team/web/manifests/latest", "acme"}, // only the first segment
		// No namespace+repo to scope to.
		{"/v2/acme", ""}, // bare namespace, no repo path
		{"/v2/", ""},
		{"/v2", ""},
		{"/v2/_catalog", ""},
		{"", ""},
	}
	for _, tc := range tests {
		if got := extractProject(tc.path); got != tc.want {
			t.Errorf("extractProject(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestIsPushRequest pins the read/write split that gates the registry.push
// permission: GET/HEAD are pulls (read); every other method (PUT/POST/PATCH/
// DELETE) is a push and requires write access.
func TestIsPushRequest(t *testing.T) {
	tests := []struct {
		method string
		want   bool
	}{
		{http.MethodGet, false},
		{http.MethodHead, false},
		{http.MethodPut, true},
		{http.MethodPost, true},
		{http.MethodPatch, true},
		{http.MethodDelete, true},
	}
	for _, tc := range tests {
		if got := isPushRequest(tc.method); got != tc.want {
			t.Errorf("isPushRequest(%q) = %v, want %v", tc.method, got, tc.want)
		}
	}
}
