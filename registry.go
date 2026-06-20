package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/acoshift/pgsql"
	"github.com/acoshift/pgsql/pgctx"
	"github.com/acoshift/pgsql/pgstmt"
	"github.com/lib/pq"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/googleapi"
)

const chunkMinLength = 5 * 1024 * 1024 // 5 MiB

// App holds shared dependencies.
type App struct {
	Bucket    *storage.BucketHandle
	CDNDomain string
}

var (
	reBlobDigest  = regexp.MustCompile(`^/v2/(.+)/blobs/(sha256:[a-f0-9]+)$`)
	reManifest    = regexp.MustCompile(`^/v2/(.+)/manifests/([^/]+)$`)
	reTags        = regexp.MustCompile(`^/v2/(.+)/tags/list$`)
	reUploadStart = regexp.MustCompile(`^/v2/(.+)/blobs/uploads/?$`)
	reUploadChunk = regexp.MustCompile(`^/v2/(.+)/blobs/uploads/([^/]+)$`)
	reCDNBlob     = regexp.MustCompile(`^/_cdn/(.+)/blobs/(sha256:[a-f0-9]+)$`)
)

func (a *App) registryHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	slog.Debug("registry request", "method", r.Method, "path", path)

	if path == "/v2/" {
		w.Write([]byte("ok"))
		return
	}

	if m := reBlobDigest.FindStringSubmatch(path); m != nil {
		name, digest := m[1], m[2]
		switch r.Method {
		case http.MethodGet:
			a.getBlob(w, r, name, digest)
		case http.MethodHead:
			a.headBlob(w, r, name, digest)
		case http.MethodDelete:
			a.deleteBlob(w, r, name, digest)
		default:
			registryError(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "the operation is unsupported")
		}
		return
	}

	if m := reManifest.FindStringSubmatch(path); m != nil {
		name, reference := m[1], m[2]
		switch r.Method {
		case http.MethodGet:
			a.getManifest(w, r, name, reference)
		case http.MethodHead:
			a.headManifest(w, r, name, reference)
		case http.MethodPut:
			a.putManifest(w, r, name, reference)
		case http.MethodDelete:
			a.deleteManifest(w, r, name, reference)
		default:
			registryError(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "the operation is unsupported")
		}
		return
	}

	if m := reTags.FindStringSubmatch(path); m != nil {
		name := m[1]
		if r.Method == http.MethodGet {
			a.listTags(w, r, name)
		} else {
			registryError(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "the operation is unsupported")
		}
		return
	}

	if m := reUploadStart.FindStringSubmatch(path); m != nil {
		name := m[1]
		if r.Method == http.MethodPost {
			a.startUpload(w, r, name)
		} else {
			registryError(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "the operation is unsupported")
		}
		return
	}

	if m := reUploadChunk.FindStringSubmatch(path); m != nil {
		name, reference := m[1], m[2]
		switch r.Method {
		case http.MethodGet:
			a.getUpload(w, r, name, reference)
		case http.MethodPatch:
			a.patchUpload(w, r, name, reference)
		case http.MethodPut:
			a.putUpload(w, r, name, reference)
		default:
			registryError(w, http.StatusMethodNotAllowed, "UNSUPPORTED", "the operation is unsupported")
		}
		return
	}

	registryError(w, http.StatusNotFound, "NAME_UNKNOWN", "repository name not known to registry")
}

// end-2 GET
func (a *App) getBlob(w http.ResponseWriter, r *http.Request, name, digest string) {
	slog.Debug("get blob", "name", name, "digest", digest)
	ctx := r.Context()
	obj := a.Bucket.Object(fmt.Sprintf("%s/blobs/%s", name, digest))
	attrs, err := obj.Attrs(ctx)
	if isNotFound(err) {
		registryError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob unknown to registry")
		return
	}
	if err != nil {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}

	if a.CDNDomain != "" && !isInternalClient(r) {
		if projectID := projectIDFromContext(ctx); projectID != "" {
			downloadCount.WithLabelValues(projectID).Inc()
			egressBytes.WithLabelValues(projectID).Add(float64(attrs.Size))
		}
		w.Header().Set("Docker-Content-Digest", digest)
		http.Redirect(w, r, "https://"+a.CDNDomain+"/"+name+"/blobs/"+digest, http.StatusTemporaryRedirect)
		return
	}

	rc, err := obj.NewReader(ctx)
	if err != nil {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	defer rc.Close()

	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", strconv.FormatInt(attrs.Size, 10))
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	n, _ := io.Copy(w, rc)

	if projectID := projectIDFromContext(ctx); projectID != "" {
		downloadCount.WithLabelValues(projectID).Inc()
		egressBytes.WithLabelValues(projectID).Add(float64(n))
	}
}

// cdnHandler serves blobs to the CDN edge. Unauthenticated — blobs are
// content-addressed and only reachable if you know the digest.
func (a *App) cdnHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	m := reCDNBlob.FindStringSubmatch(r.URL.Path)
	if m == nil {
		http.NotFound(w, r)
		return
	}
	name, digest := m[1], m[2]
	slog.Debug("cdn blob", "name", name, "digest", digest)

	ctx := r.Context()
	obj := a.Bucket.Object(fmt.Sprintf("%s/blobs/%s", name, digest))
	attrs, err := obj.Attrs(ctx)
	if isNotFound(err) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", strconv.FormatInt(attrs.Size, 10))
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	rc, err := obj.NewReader(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rc.Close()
	io.Copy(w, rc)
}

// end-2 HEAD
func (a *App) headBlob(w http.ResponseWriter, r *http.Request, name, digest string) {
	slog.Debug("head blob", "name", name, "digest", digest)
	ctx := r.Context()
	attrs, err := a.Bucket.Object(fmt.Sprintf("%s/blobs/%s", name, digest)).Attrs(ctx)
	if isNotFound(err) {
		registryError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob unknown to registry")
		return
	}
	if err != nil {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}

	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", strconv.FormatInt(attrs.Size, 10))
	w.WriteHeader(http.StatusOK)
}

// end-3 GET
func (a *App) getManifest(w http.ResponseWriter, r *http.Request, name, reference string) {
	slog.Debug("get manifest", "name", name, "reference", reference)
	ctx := r.Context()
	obj := a.Bucket.Object(fmt.Sprintf("%s/manifests/%s", name, reference))
	attrs, err := obj.Attrs(ctx)
	if isNotFound(err) {
		registryError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest unknown to registry")
		return
	}
	if err != nil {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}

	digest := attrs.Metadata["docker-content-digest"]
	if digest == "" {
		digest = reference
	}

	rc, err := obj.NewReader(ctx)
	if err != nil {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	defer rc.Close()

	maxAge := 600
	if strings.HasPrefix(reference, "sha256:") {
		maxAge = 86400
	}

	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", strconv.FormatInt(attrs.Size, 10))
	w.Header().Set("Content-Type", attrs.ContentType)
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))
	io.Copy(w, rc)
}

// end-3 HEAD
func (a *App) headManifest(w http.ResponseWriter, r *http.Request, name, reference string) {
	slog.Debug("head manifest", "name", name, "reference", reference)
	ctx := r.Context()
	attrs, err := a.Bucket.Object(fmt.Sprintf("%s/manifests/%s", name, reference)).Attrs(ctx)
	if isNotFound(err) {
		registryError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest unknown to registry")
		return
	}
	if err != nil {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}

	digest := attrs.Metadata["docker-content-digest"]
	if digest == "" {
		digest = reference
	}

	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", strconv.FormatInt(attrs.Size, 10))
	w.Header().Set("Content-Type", attrs.ContentType)
	w.WriteHeader(http.StatusOK)
}

// end-4a, end-4b, end-11
func (a *App) startUpload(w http.ResponseWriter, r *http.Request, name string) {
	slog.Debug("start upload", "name", name)
	ctx := r.Context()
	q := r.URL.Query()
	mount := q.Get("mount")
	from := q.Get("from")
	digest := q.Get("digest")
	origin := q.Get("origin")

	projectID := projectIDFromContext(ctx)

	// end-11: cross-repo mount
	if mount != "" && from != "" {
		if _, err := a.Bucket.Object(fmt.Sprintf("%s/blobs/%s", name, mount)).Attrs(ctx); err == nil {
			w.Header().Set("Location", "/v2/"+name+"/blobs/"+mount)
			w.Header().Set("Docker-Content-Digest", mount)
			w.WriteHeader(http.StatusCreated)
			return
		}

		if origin != "" {
			resp, err := http.Get("https://" + origin + "/v2/" + from + "/blobs/" + mount)
			if err == nil && resp.StatusCode == http.StatusOK {
				defer resp.Body.Close()
				size, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
				if err := a.writeBlob(ctx, name, mount, resp.Body); err == nil {
					if err := a.insertBlob(ctx, name, mount, size); err != nil {
						registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
						return
					}
					if projectID != "" {
						uploadCount.WithLabelValues(projectID).Inc()
						uploadBytes.WithLabelValues(projectID).Add(float64(size))
					}
					w.Header().Set("Location", "/v2/"+name+"/blobs/"+mount)
					w.Header().Set("Docker-Content-Digest", mount)
					w.WriteHeader(http.StatusCreated)
					return
				}
			}
		} else {
			src := a.Bucket.Object(fmt.Sprintf("%s/blobs/%s", from, mount))
			if srcAttrs, err := src.Attrs(ctx); err == nil {
				dst := a.Bucket.Object(fmt.Sprintf("%s/blobs/%s", name, mount))
				if _, err := dst.CopierFrom(src).Run(ctx); err == nil {
					if err := a.insertBlob(ctx, name, mount, srcAttrs.Size); err != nil {
						registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
						return
					}
					if projectID != "" {
						uploadCount.WithLabelValues(projectID).Inc()
						uploadBytes.WithLabelValues(projectID).Add(float64(srcAttrs.Size))
					}
					w.Header().Set("Location", "/v2/"+name+"/blobs/"+mount)
					w.Header().Set("Docker-Content-Digest", mount)
					w.WriteHeader(http.StatusCreated)
					return
				}
			}
		}
		// fallthrough to end-4a
	}

	// end-4b: monolithic upload with digest
	if digest != "" {
		if _, err := a.Bucket.Object(fmt.Sprintf("%s/blobs/%s", name, digest)).Attrs(ctx); err != nil {
			if err := a.writeBlob(ctx, name, digest, r.Body); err != nil {
				registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
				return
			}
			if projectID != "" {
				size := max(r.ContentLength, 0)
				uploadCount.WithLabelValues(projectID).Inc()
				uploadBytes.WithLabelValues(projectID).Add(float64(size))
			}
		}
		w.Header().Set("Location", "/v2/"+name+"/blobs/"+digest)
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusCreated)
		return
	}

	// end-4a: initiate chunked upload
	reference := newUUID()
	state := uploadState{Size: 0, Parts: 0}
	w.Header().Set("Location", uploadLocation(name, reference, state))
	w.Header().Set("OCI-Chunk-Min-Length", strconv.Itoa(chunkMinLength))
	w.WriteHeader(http.StatusAccepted)
}

// end-5: upload chunk
func (a *App) patchUpload(w http.ResponseWriter, r *http.Request, name, reference string) {
	slog.Debug("patch upload", "name", name, "reference", reference,
		"content-length", r.Header.Get("Content-Length"),
		"content-range", r.Header.Get("Content-Range"))
	q := r.URL.Query()
	stateStr := q.Get("state")
	if stateStr == "" {
		registryError(w, http.StatusBadRequest, "UNSUPPORTED", "the operation is unsupported")
		return
	}

	var state uploadState
	if err := json.Unmarshal([]byte(stateStr), &state); err != nil {
		registryError(w, http.StatusBadRequest, "UNSUPPORTED", "the operation is unsupported")
		return
	}

	rangeStart := state.Size
	if cr := r.Header.Get("Content-Range"); cr != "" {
		if parts := strings.SplitN(cr, "-", 2); len(parts) == 2 {
			rangeStart, _ = strconv.ParseInt(parts[0], 10, 64)
		}
	}
	if state.Size != rangeStart {
		slog.Debug("patch upload range mismatch", "state.size", state.Size, "range-start", rangeStart)
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}

	ctx := r.Context()
	partNum := state.Parts + 1
	partObj := a.Bucket.Object(fmt.Sprintf("_uploads/%s/%d", reference, partNum))
	wc := partObj.NewWriter(ctx)
	n, err := io.Copy(wc, r.Body)
	if err != nil {
		wc.Close()
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	if err := wc.Close(); err != nil {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}

	if n > 0 {
		state.Size += n
		state.Parts = partNum
		slog.Debug("patch upload chunk written", "name", name, "part", partNum, "bytes", n, "total", state.Size)
	} else {
		// empty chunk — discard the empty object
		partObj.Delete(ctx)
		slog.Debug("patch upload empty chunk ignored", "name", name, "reference", reference)
	}

	end := max(state.Size-1, 0)
	w.Header().Set("Location", uploadLocation(name, reference, state))
	w.Header().Set("Range", fmt.Sprintf("0-%d", end))
	w.WriteHeader(http.StatusAccepted)
}

// end-6: finalize upload
func (a *App) putUpload(w http.ResponseWriter, r *http.Request, name, reference string) {
	slog.Debug("put upload", "name", name, "reference", reference)
	q := r.URL.Query()
	stateStr := q.Get("state")
	digest := q.Get("digest")
	if stateStr == "" || digest == "" {
		registryError(w, http.StatusBadRequest, "UNSUPPORTED", "the operation is unsupported")
		return
	}

	var state uploadState
	if err := json.Unmarshal([]byte(stateStr), &state); err != nil {
		registryError(w, http.StatusBadRequest, "UNSUPPORTED", "the operation is unsupported")
		return
	}

	ctx := r.Context()

	contentLength, _ := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)
	if contentLength > 0 {
		partNum := state.Parts + 1
		wc := a.Bucket.Object(fmt.Sprintf("_uploads/%s/%d", reference, partNum)).NewWriter(ctx)
		n, err := io.Copy(wc, r.Body)
		if err != nil {
			wc.Close()
			registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
			return
		}
		if err := wc.Close(); err != nil {
			registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
			return
		}
		state.Size += n
		state.Parts = partNum
	}

	if err := a.composeParts(ctx, reference, state.Parts, name, digest); err != nil {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}

	if err := a.insertBlob(ctx, name, digest, state.Size); err != nil {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}

	if projectID := projectIDFromContext(ctx); projectID != "" {
		uploadCount.WithLabelValues(projectID).Inc()
		uploadBytes.WithLabelValues(projectID).Add(float64(state.Size))
	}

	w.Header().Set("Location", "/v2/"+name+"/blobs/"+digest)
	w.Header().Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusCreated)
}

// end-13: get upload status
func (a *App) getUpload(w http.ResponseWriter, r *http.Request, name, reference string) {
	slog.Debug("get upload", "name", name, "reference", reference)
	q := r.URL.Query()
	stateStr := q.Get("state")
	if stateStr == "" {
		registryError(w, http.StatusBadRequest, "UNSUPPORTED", "the operation is unsupported")
		return
	}

	var state uploadState
	if err := json.Unmarshal([]byte(stateStr), &state); err != nil {
		registryError(w, http.StatusBadRequest, "UNSUPPORTED", "the operation is unsupported")
		return
	}

	w.Header().Set("Location", uploadLocation(name, reference, state))
	w.Header().Set("Range", fmt.Sprintf("0-%d", state.Size))
	w.WriteHeader(http.StatusNoContent)
}

// end-7
func (a *App) putManifest(w http.ResponseWriter, r *http.Request, name, reference string) {
	slog.Debug("put manifest", "name", name, "reference", reference)
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		registryError(w, http.StatusBadRequest, "UNSUPPORTED", "the operation is unsupported")
		return
	}

	ctx := r.Context()
	namespace := namespaceFromContext(ctx)

	h := sha256.New()
	body, err := io.ReadAll(io.TeeReader(r.Body, h))
	if err != nil {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	digest := fmt.Sprintf("sha256:%x", h.Sum(nil))
	slog.Debug("manifest digest computed", "name", name, "reference", reference, "digest", digest)

	writeManifestObj := func(objPath string) error {
		wc := a.Bucket.Object(objPath).NewWriter(ctx)
		wc.ContentType = contentType
		wc.ObjectAttrs.Metadata = map[string]string{"docker-content-digest": digest}
		if _, err := wc.Write(body); err != nil {
			wc.Close()
			return err
		}
		return wc.Close()
	}

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return writeManifestObj(fmt.Sprintf("%s/manifests/%s", name, digest)) })
	if digest != reference {
		g.Go(func() error { return writeManifestObj(fmt.Sprintf("%s/manifests/%s", name, reference)) })
	}
	_ = gctx
	if err := g.Wait(); err != nil {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}

	if _, err := pgctx.Exec(ctx, `
		insert into repositories (name, namespace)
		values ($1, $2)
		on conflict do nothing
	`, name, namespace); err != nil {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	if _, err := pgctx.Exec(ctx, `
		insert into manifests (repository, digest)
		values ($1, $2)
		on conflict do nothing
	`, name, digest); err != nil {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	if digest != reference {
		if _, err := pgctx.Exec(ctx, `
			insert into tags (repository, tag, digest)
			values ($1, $2, $3)
			on conflict (repository, tag)
			do update set
				digest = excluded.digest,
				created_at = now()
		`, name, reference, digest); err != nil {
			registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
			return
		}
	}

	if err := a.indexManifest(ctx, name, digest, body); err != nil {
		slog.Error("index manifest", "name", name, "digest", digest, "error", err)
		// non-fatal: index can be rebuilt later
	}

	w.Header().Set("Location", "/v2/"+name+"/manifests/"+reference)
	w.Header().Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusCreated)
}

// end-8
func (a *App) listTags(w http.ResponseWriter, r *http.Request, name string) {
	slog.Debug("list tags", "name", name)
	ctx := r.Context()
	q := r.URL.Query()
	limit := 50
	if n := q.Get("n"); n != "" {
		if v, err := strconv.Atoi(n); err == nil && v > 0 {
			limit = v
		}
	}
	last := q.Get("last")

	tags := []string{}
	err := pgctx.Iter(ctx, func(scan pgsql.Scanner) error {
		var tag string
		if err := scan(&tag); err != nil {
			return err
		}
		tags = append(tags, tag)
		return nil
	}, `
		select tag from tags
		where repository = $1
		  and ($2 = '' or tag > $2)
		order by tag
		limit $3
	`, name, last, limit)
	if err != nil {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if len(tags) >= limit && len(tags) > 0 {
		lastTag := tags[len(tags)-1]
		qs := url.Values{"n": {strconv.Itoa(limit)}, "last": {lastTag}}
		w.Header().Set("Link", fmt.Sprintf("</v2/%s/tags/list?%s>; rel=next", name, qs.Encode()))
	}
	json.NewEncoder(w).Encode(map[string]any{"name": name, "tags": tags})
}

// end-9
func (a *App) deleteManifest(w http.ResponseWriter, r *http.Request, name, reference string) {
	slog.Debug("delete manifest", "name", name, "reference", reference)
	ctx := r.Context()
	obj := a.Bucket.Object(fmt.Sprintf("%s/manifests/%s", name, reference))
	if _, err := obj.Attrs(ctx); isNotFound(err) {
		registryError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest unknown to registry")
		return
	}
	if err := obj.Delete(ctx); err != nil && !isNotFound(err) {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}

	if strings.HasPrefix(reference, "sha256:") {
		// Collect tags pointing to this manifest so we can delete their GCS objects.
		var tags []string
		_ = pgctx.Iter(ctx, func(scan pgsql.Scanner) error {
			var tag string
			if err := scan(&tag); err != nil {
				return err
			}
			tags = append(tags, tag)
			return nil
		}, `select tag from tags where repository = $1 and digest = $2`, name, reference)
		for _, tag := range tags {
			// best-effort; ignore errors
			a.Bucket.Object(fmt.Sprintf("%s/manifests/%s", name, tag)).Delete(ctx)
		}

		// Delete dependent rows before manifests (FK constraints have no CASCADE).
		for _, q := range []string{
			`delete from manifest_blobs where repository = $1 and manifest_digest = $2`,
			`delete from tags            where repository = $1 and digest         = $2`,
			`delete from manifests       where repository = $1 and digest         = $2`,
		} {
			if _, err := pgctx.Exec(ctx, q, name, reference); err != nil {
				registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
				return
			}
		}
	} else {
		if _, err := pgctx.Exec(ctx, `delete from tags where repository = $1 and tag = $2`, name, reference); err != nil {
			registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
			return
		}
	}

	w.WriteHeader(http.StatusAccepted)
}

// end-10
func (a *App) deleteBlob(w http.ResponseWriter, r *http.Request, name, digest string) {
	slog.Debug("delete blob", "name", name, "digest", digest)
	ctx := r.Context()
	obj := a.Bucket.Object(fmt.Sprintf("%s/blobs/%s", name, digest))
	if _, err := obj.Attrs(ctx); isNotFound(err) {
		registryError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob unknown to registry")
		return
	}
	if err := obj.Delete(ctx); err != nil && !isNotFound(err) {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}

	if _, err := pgctx.Exec(ctx, `delete from blobs where repository = $1 and digest = $2`, name, digest); err != nil {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

// storage helpers

func (a *App) writeBlob(ctx context.Context, name, digest string, body io.Reader) error {
	wc := a.Bucket.Object(fmt.Sprintf("%s/blobs/%s", name, digest)).NewWriter(ctx)
	wc.ObjectAttrs.Metadata = map[string]string{"docker-content-digest": digest}
	if _, err := io.Copy(wc, body); err != nil {
		wc.Close()
		return err
	}
	return wc.Close()
}

// composeParts merges partCount chunk objects (_uploads/{reference}/1..N) into the final blob.
// Uses staged composition to handle >32 parts (GCS limit per compose call).
func (a *App) composeParts(ctx context.Context, reference string, partCount int, name, digest string) error {
	finalDst := a.Bucket.Object(fmt.Sprintf("%s/blobs/%s", name, digest))

	if partCount == 0 {
		wc := finalDst.NewWriter(ctx)
		return wc.Close()
	}

	srcs := make([]*storage.ObjectHandle, partCount)
	for i := range srcs {
		srcs[i] = a.Bucket.Object(fmt.Sprintf("_uploads/%s/%d", reference, i+1))
	}

	const maxCompose = 32
	var stageTempObjects []*storage.ObjectHandle
	stage := 0

	for len(srcs) > maxCompose {
		var next []*storage.ObjectHandle
		for i := 0; i < len(srcs); i += maxCompose {
			end := min(i+maxCompose, len(srcs))
			batch := srcs[i:end]
			stageDst := a.Bucket.Object(fmt.Sprintf("_uploads/%s/stage-%d-%d", reference, stage, len(next)))
			stageTempObjects = append(stageTempObjects, stageDst)
			if _, err := stageDst.ComposerFrom(batch...).Run(ctx); err != nil {
				return err
			}
			next = append(next, stageDst)
		}
		srcs = next
		stage++
	}

	if len(srcs) == 1 {
		_, err := finalDst.CopierFrom(srcs[0]).Run(ctx)
		if err != nil {
			return err
		}
	} else {
		if _, err := finalDst.ComposerFrom(srcs...).Run(ctx); err != nil {
			return err
		}
	}

	go func() {
		for i := 1; i <= partCount; i++ {
			a.Bucket.Object(fmt.Sprintf("_uploads/%s/%d", reference, i)).Delete(context.Background())
		}
		for _, obj := range stageTempObjects {
			obj.Delete(context.Background())
		}
	}()

	return nil
}

type manifestContent struct {
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
	// Manifests is the child list of an image index / manifest list (multi-arch).
	// An index references sub-manifests by digest and has no config/layers of its
	// own, so its size is the sum of those children's sizes.
	Manifests []struct {
		Digest string `json:"digest"`
	} `json:"manifests"`
}

// dedupeDigests returns the non-empty digests of v with duplicates removed.
func dedupeDigests[T any](v []T, digest func(T) string) []string {
	seen := make(map[string]struct{}, len(v))
	out := make([]string, 0, len(v))
	for _, it := range v {
		d := digest(it)
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

// indexManifest parses a manifest body, records which blobs it references (for
// image manifests), and stores the manifest's size:
//   - image manifest: size is the sum of its blob sizes (config + layers).
//   - image index / manifest list: size is the sum of its children's sizes; if
//     any child is not yet indexed, size is left NULL so the next index pass
//     retries once the children have been sized.
func (a *App) indexManifest(ctx context.Context, repository, manifestDigest string, body []byte) error {
	var m manifestContent
	if err := json.Unmarshal(body, &m); err != nil {
		return err
	}

	// Image index / manifest list: sum the children's sizes.
	if len(m.Manifests) > 0 {
		children := dedupeDigests(m.Manifests, func(c struct {
			Digest string `json:"digest"`
		}) string {
			return c.Digest
		})
		if len(children) == 0 {
			return a.setManifestSize(ctx, repository, manifestDigest, 0)
		}
		var total int64
		var sized int
		if err := pgctx.QueryRow(ctx, `
			select coalesce(sum(size), 0), count(*)
			from manifests
			where repository = $1 and digest = any($2::text[]) and size is not null
		`, repository, pq.Array(children)).Scan(&total, &sized); err != nil {
			return err
		}
		if sized < len(children) {
			// Some children aren't sized yet — leave NULL so a later pass retries.
			return nil
		}
		return a.setManifestSize(ctx, repository, manifestDigest, total)
	}

	// Image manifest: record blob references, then size = sum of those blobs.
	blobs := dedupeDigests(append([]struct {
		Digest string `json:"digest"`
	}{m.Config}, m.Layers...), func(l struct {
		Digest string `json:"digest"`
	}) string {
		return l.Digest
	})
	if len(blobs) > 0 {
		_, err := pgstmt.Insert(func(b pgstmt.InsertStatement) {
			b.Into("manifest_blobs")
			b.Columns("repository", "manifest_digest", "blob_digest")
			for _, blobDigest := range blobs {
				b.Value(repository, manifestDigest, blobDigest)
			}
			b.OnConflictDoNothing()
		}).ExecWith(ctx)
		if err != nil {
			return err
		}
	}
	return a.sizeImageFromBlobs(ctx, repository, manifestDigest)
}

func (a *App) setManifestSize(ctx context.Context, repository, manifestDigest string, size int64) error {
	_, err := pgctx.Exec(ctx, `
		update manifests
		set size = $3, updated_at = now()
		where repository = $1 and digest = $2
	`, repository, manifestDigest, size)
	return err
}

func (a *App) readManifestBody(ctx context.Context, repository, digest string) ([]byte, error) {
	obj := a.Bucket.Object(fmt.Sprintf("%s/manifests/%s", repository, digest))
	rc, err := obj.NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// rebuildManifestBlobsIndex fetches every manifest whose size has not been
// computed yet, reads its content from GCS, and indexes it (blob refs + size).
// Image manifests are processed before image indexes so an index can sum its
// already-sized children within a single pass.
func (a *App) rebuildManifestBlobsIndex(ctx context.Context) error {
	type manifestID struct {
		repository string
		digest     string
	}

	type unindexedManifest struct {
		manifestID
		hasBlobs bool
	}
	var unindexed []unindexedManifest
	err := pgctx.Iter(ctx, func(scan pgsql.Scanner) error {
		var m unindexedManifest
		if err := scan(&m.repository, &m.digest, &m.hasBlobs); err != nil {
			return err
		}
		unindexed = append(unindexed, m)
		return nil
	}, `
		select
			m.repository,
			m.digest,
			exists (
				select 1 from manifest_blobs mb
				where mb.repository = m.repository and mb.manifest_digest = m.digest
			)
		from manifests m
		where m.size is null
	`)
	if err != nil {
		return fmt.Errorf("query unindexed manifests: %w", err)
	}
	if len(unindexed) == 0 {
		return nil
	}

	slog.Info("indexing manifests", "count", len(unindexed))
	type pending struct {
		id   manifestID
		body []byte
	}
	var indexes []pending // image indexes, deferred until images are sized
	indexed := 0
	for _, m := range unindexed {
		// Already-indexed image: its blob refs exist, so size can be recomputed
		// from the DB without re-reading the manifest body from GCS.
		if m.hasBlobs {
			if err := a.sizeImageFromBlobs(ctx, m.repository, m.digest); err != nil {
				slog.Warn("size manifest from blobs", "repository", m.repository, "digest", m.digest, "error", err)
				continue
			}
			indexed++
			continue
		}
		// No blob refs yet: either an image index (references child manifests) or
		// an un-indexed image. Read the body to tell them apart.
		body, err := a.readManifestBody(ctx, m.repository, m.digest)
		if err != nil {
			slog.Warn("read manifest for indexing", "repository", m.repository, "digest", m.digest, "error", err)
			continue
		}
		var mc manifestContent
		if err := json.Unmarshal(body, &mc); err == nil && len(mc.Manifests) > 0 {
			indexes = append(indexes, pending{id: m.manifestID, body: body})
			continue
		}
		if err := a.indexManifest(ctx, m.repository, m.digest, body); err != nil {
			slog.Warn("index manifest", "repository", m.repository, "digest", m.digest, "error", err)
			continue
		}
		indexed++
	}
	// Indexes last, so their (now-sized) children are summed correctly.
	for _, ix := range indexes {
		if err := a.indexManifest(ctx, ix.id.repository, ix.id.digest, ix.body); err != nil {
			slog.Warn("index manifest", "repository", ix.id.repository, "digest", ix.id.digest, "error", err)
			continue
		}
		indexed++
	}
	slog.Info("indexing complete", "indexed", indexed, "total", len(unindexed))
	return nil
}

// sizeImageFromBlobs sets an image manifest's size from its already-recorded
// blob references, without re-reading the manifest body.
func (a *App) sizeImageFromBlobs(ctx context.Context, repository, manifestDigest string) error {
	var total int64
	if err := pgctx.QueryRow(ctx, `
		select coalesce(sum(b.size), 0)
		from manifest_blobs mb
		join blobs b on b.repository = mb.repository and b.digest = mb.blob_digest
		where mb.repository = $1 and mb.manifest_digest = $2
	`, repository, manifestDigest).Scan(&total); err != nil {
		return err
	}
	return a.setManifestSize(ctx, repository, manifestDigest, total)
}

func (a *App) insertBlob(ctx context.Context, name, digest string, size int64) error {
	_, err := pgctx.Exec(ctx, `
		insert into blobs (repository, digest, size)
		values ($1, $2, $3)
		on conflict do nothing
	`, name, digest, size)
	return err
}

// upload state threaded through URL query params

type uploadState struct {
	Size  int64 `json:"s"`
	Parts int   `json:"p"`
}

func uploadLocation(name, reference string, state uploadState) string {
	stateJSON, _ := json.Marshal(state)
	q := url.Values{"state": {string(stateJSON)}}
	return fmt.Sprintf("/v2/%s/blobs/uploads/%s?%s", name, reference, q.Encode())
}

// registry error response helpers

type registryErrorItem struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail"`
}

type registryErrorBody struct {
	Errors []registryErrorItem `json:"errors"`
}

func registryError(w http.ResponseWriter, status int, code, message string) {
	if status >= 500 {
		slog.Error("registry error", "status", status, "code", code, "message", message)
	} else {
		slog.Debug("registry error", "status", status, "code", code, "message", message)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(registryErrorBody{
		Errors: []registryErrorItem{{Code: code, Message: message, Detail: message}},
	})
}

// isInternalClient returns true when the request originates from a
// private/loopback/link-local IP per the X-Real-Ip header. Internal callers
// (in-cluster pulls) bypass the CDN redirect and read blobs directly.
func isInternalClient(r *http.Request) bool {
	ip := net.ParseIP(r.Header.Get("X-Real-Ip"))
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func isNotFound(err error) bool {
	if errors.Is(err, storage.ErrObjectNotExist) {
		return true
	}
	if e, ok := errors.AsType[*googleapi.Error](err); ok {
		return e.Code == http.StatusNotFound
	}
	return false
}

func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
