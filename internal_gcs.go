package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"cloud.google.com/go/storage"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
)

// GCS-object cleanup for the registry management API. The management API itself
// now lives in the apiserver (which owns the registry.* tables): it deletes the
// DB rows and calls these internal endpoints to remove the corresponding GCS
// objects, so the bucket credentials stay in the registry service.

// deleteRepositoryObjects removes every GCS object under the repository prefix
// "{fullName}/" (fullName is the full "{namespace}/{repo}" name).
func (a *App) deleteRepositoryObjects(ctx context.Context, fullName string) error {
	it := a.Bucket.Objects(ctx, &storage.Query{
		Prefix:     fullName + "/",
		Projection: storage.ProjectionNoACL,
	})
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		if err := a.Bucket.Object(attrs.Name).Delete(ctx); err != nil && !isNotFound(err) {
			return err
		}
	}
	return nil
}

// deleteManifestObjects removes the digest-addressed manifest object plus each
// tag-addressed manifest object, in parallel.
func (a *App) deleteManifestObjects(ctx context.Context, fullName, digest string, tags []string) error {
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		obj := a.Bucket.Object(fmt.Sprintf("%s/manifests/%s", fullName, digest))
		if err := obj.Delete(gctx); err != nil && !isNotFound(err) {
			return err
		}
		return nil
	})
	for _, tag := range tags {
		g.Go(func() error {
			obj := a.Bucket.Object(fmt.Sprintf("%s/manifests/%s", fullName, tag))
			if err := obj.Delete(gctx); err != nil && !isNotFound(err) {
				return err
			}
			return nil
		})
	}
	return g.Wait()
}

// deleteTagObject removes the tag-addressed manifest object (best-effort).
func (a *App) deleteTagObject(ctx context.Context, fullName, tag string) error {
	obj := a.Bucket.Object(fmt.Sprintf("%s/manifests/%s", fullName, tag))
	if err := obj.Delete(ctx); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

// mountInternalGCS registers the internal GCS-cleanup endpoints the apiserver
// calls after it has deleted the registry rows. Protected by internalAuth.
func (a *App) mountInternalGCS(mux *http.ServeMux, internalAuth func(http.ResponseWriter, *http.Request) bool) {
	mux.HandleFunc("POST /internal/registry/deleteRepository", func(w http.ResponseWriter, r *http.Request) {
		if !internalAuth(w, r) {
			return
		}
		var req struct {
			Repository string `json:"repository"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Detach so a large prefix delete completes even if the caller drops.
		if err := a.deleteRepositoryObjects(context.WithoutCancel(r.Context()), req.Repository); err != nil {
			slog.Error("deleteRepositoryObjects", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("POST /internal/registry/deleteManifest", func(w http.ResponseWriter, r *http.Request) {
		if !internalAuth(w, r) {
			return
		}
		var req struct {
			Repository string   `json:"repository"`
			Digest     string   `json:"digest"`
			Tags       []string `json:"tags"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := a.deleteManifestObjects(r.Context(), req.Repository, req.Digest, req.Tags); err != nil {
			slog.Error("deleteManifestObjects", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("POST /internal/registry/untag", func(w http.ResponseWriter, r *http.Request) {
		if !internalAuth(w, r) {
			return
		}
		var req struct {
			Repository string `json:"repository"`
			Tag        string `json:"tag"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := a.deleteTagObject(r.Context(), req.Repository, req.Tag); err != nil {
			slog.Error("deleteTagObject", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
