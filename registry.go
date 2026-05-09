package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/acoshift/pgsql"
	"github.com/acoshift/pgsql/pgctx"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/googleapi"
)

const chunkMinLength = 5 * 1024 * 1024 // 5 MiB

// App holds shared dependencies.
type App struct {
	Bucket *storage.BucketHandle
	DB     *sql.DB
}

var (
	reBlobDigest  = regexp.MustCompile(`^/v2/(.+)/blobs/(sha256:[a-f0-9]+)$`)
	reManifest    = regexp.MustCompile(`^/v2/(.+)/manifests/([^/]+)$`)
	reTags        = regexp.MustCompile(`^/v2/(.+)/tags/list$`)
	reUploadStart = regexp.MustCompile(`^/v2/(.+)/blobs/uploads/?$`)
	reUploadChunk = regexp.MustCompile(`^/v2/(.+)/blobs/uploads/([^/]+)$`)
)

func (a *App) registryHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

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

	rc, err := obj.NewReader(ctx)
	if err != nil {
		registryError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	defer rc.Close()

	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", strconv.FormatInt(attrs.Size, 10))
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	io.Copy(w, rc)
}

// end-2 HEAD
func (a *App) headBlob(w http.ResponseWriter, r *http.Request, name, digest string) {
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
	ctx := r.Context()
	q := r.URL.Query()
	mount := q.Get("mount")
	from := q.Get("from")
	digest := q.Get("digest")
	origin := q.Get("origin")

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
					go a.insertBlob(name, mount, size)
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
					go a.insertBlob(name, mount, srcAttrs.Size)
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

	contentLength, _ := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)
	if contentLength == 0 {
		registryError(w, http.StatusBadRequest, "UNSUPPORTED", "empty body")
		return
	}

	rangeStart := state.Size
	if cr := r.Header.Get("Content-Range"); cr != "" {
		if parts := strings.SplitN(cr, "-", 2); len(parts) == 2 {
			rangeStart, _ = strconv.ParseInt(parts[0], 10, 64)
		}
	}
	if state.Size != rangeStart {
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}

	ctx := r.Context()
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

	w.Header().Set("Location", uploadLocation(name, reference, state))
	w.WriteHeader(http.StatusAccepted)
}

// end-6: finalize upload
func (a *App) putUpload(w http.ResponseWriter, r *http.Request, name, reference string) {
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

	go a.insertBlob(name, digest, state.Size)

	w.Header().Set("Location", "/v2/"+name+"/blobs/"+digest)
	w.Header().Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusCreated)
}

// end-13: get upload status
func (a *App) getUpload(w http.ResponseWriter, r *http.Request, name, reference string) {
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

	go func() {
		db := a.DB
		db.ExecContext(context.Background(), `
			insert into repositories (name, namespace)
			values ($1, $2)
			on conflict do nothing
		`, name, namespace)
		db.ExecContext(context.Background(), `
			insert into manifests (repository, digest)
			values ($1, $2)
			on conflict do nothing
		`, name, digest)
		if digest != reference {
			db.ExecContext(context.Background(), `
				insert into tags (repository, tag, digest)
				values ($1, $2, $3)
				on conflict (repository, tag)
				do update set
					digest = excluded.digest,
					created_at = now()
			`, name, reference, digest)
		}
	}()

	w.Header().Set("Location", "/v2/"+name+"/manifests/"+reference)
	w.Header().Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusCreated)
}

// end-8
func (a *App) listTags(w http.ResponseWriter, r *http.Request, name string) {
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

	go func() {
		if strings.HasPrefix(reference, "sha256:") {
			a.DB.ExecContext(context.Background(), `delete from manifests where repository = $1 and digest = $2`, name, reference)
		} else {
			a.DB.ExecContext(context.Background(), `delete from tags where repository = $1 and tag = $2`, name, reference)
		}
	}()

	w.WriteHeader(http.StatusAccepted)
}

// end-10
func (a *App) deleteBlob(w http.ResponseWriter, r *http.Request, name, digest string) {
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

	go a.DB.ExecContext(context.Background(), `delete from blobs where repository = $1 and digest = $2`, name, digest)

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
			end := i + maxCompose
			if end > len(srcs) {
				end = len(srcs)
			}
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

func (a *App) insertBlob(name, digest string, size int64) {
	a.DB.ExecContext(context.Background(), `
		insert into blobs (repository, digest, size)
		values ($1, $2, $3)
		on conflict do nothing
	`, name, digest, size)
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

func registryError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]any{
			{"code": code, "message": message, "detail": message},
		},
	})
}

func isNotFound(err error) bool {
	if errors.Is(err, storage.ErrObjectNotExist) {
		return true
	}
	var e *googleapi.Error
	if errors.As(err, &e) {
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
