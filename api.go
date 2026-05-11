package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/acoshift/arpc/v2"
	"github.com/acoshift/pgsql"
	"github.com/acoshift/pgsql/pgctx"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
)

func (a *App) mountAPI(mux *http.ServeMux) {
	m := arpc.New()
	api := http.NewServeMux()
	api.Handle("POST /api/list", m.Handler(a.apiList))
	api.Handle("POST /api/get", m.Handler(a.apiGet))
	api.Handle("POST /api/getTags", m.Handler(a.apiGetTags))
	api.Handle("POST /api/getManifests", m.Handler(a.apiGetManifests))
	api.Handle("POST /api/getProjectStorage", m.Handler(a.apiGetProjectStorage))
	api.Handle("POST /api/delete", m.Handler(a.apiDelete))
	api.Handle("POST /api/deleteManifest", m.Handler(a.apiDeleteManifest))
	api.Handle("POST /api/untag", m.Handler(a.apiUntag))
	mux.Handle("/api/", apiAuthMiddleware(api))
}

// list

type apiListRequest struct {
	Project string `json:"project"`
}

func (r *apiListRequest) Valid() error {
	if r.Project == "" {
		return arpc.NewError("project required")
	}
	return nil
}

type apiListItem struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

type apiListResult struct {
	Items []apiListItem `json:"items"`
}

func (a *App) apiList(ctx context.Context, req *apiListRequest) (*apiListResult, error) {
	if !checkPermission(ctx, req.Project, permList) {
		return nil, errForbidden
	}

	var items []apiListItem
	prefix := req.Project + "/"
	err := pgctx.Iter(ctx, func(scan pgsql.Scanner) error {
		var name string
		var createdAt time.Time
		if err := scan(&name, &createdAt); err != nil {
			return err
		}
		items = append(items, apiListItem{
			Name:      strings.TrimPrefix(name, prefix),
			CreatedAt: createdAt,
		})
		return nil
	}, `
		select name, created_at
		from repositories
		where namespace = $1
		order by name
	`, req.Project)
	if err != nil {
		return nil, err
	}

	if items == nil {
		items = []apiListItem{}
	}
	return &apiListResult{Items: items}, nil
}

// get

type apiGetRequest struct {
	Project    string `json:"project"`
	Repository string `json:"repository"`
}

func (r *apiGetRequest) Valid() error {
	if r.Project == "" {
		return arpc.NewError("project required")
	}
	if r.Repository == "" {
		return arpc.NewError("repository required")
	}
	return nil
}

type apiGetResult struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"createdAt"`
}

func (a *App) apiGet(ctx context.Context, req *apiGetRequest) (*apiGetResult, error) {
	if !checkPermission(ctx, req.Project, permGet) {
		return nil, errForbidden
	}

	fullName := req.Project + "/" + req.Repository

	var name string
	var createdAt time.Time
	err := pgctx.QueryRow(ctx, `
		select name, created_at
		from repositories
		where name = $1 and namespace = $2
	`, fullName, req.Project).Scan(&name, &createdAt)
	if err != nil {
		return nil, errRepoNotFound
	}

	var size int64
	pgctx.QueryRow(ctx, `
		select coalesce(sum(size), 0) from blobs where repository = $1
	`, fullName).Scan(&size)

	return &apiGetResult{
		Name:      strings.TrimPrefix(name, req.Project+"/"),
		Size:      size,
		CreatedAt: createdAt,
	}, nil
}

// getTags

type apiGetTagsRequest struct {
	Project    string `json:"project"`
	Repository string `json:"repository"`
}

func (r *apiGetTagsRequest) Valid() error {
	if r.Project == "" {
		return arpc.NewError("project required")
	}
	if r.Repository == "" {
		return arpc.NewError("repository required")
	}
	return nil
}

type apiTagItem struct {
	Tag       string    `json:"tag"`
	Digest    string    `json:"digest"`
	CreatedAt time.Time `json:"createdAt"`
}

type apiGetTagsResult struct {
	Name  string       `json:"name"`
	Items []apiTagItem `json:"items"`
}

func (a *App) apiGetTags(ctx context.Context, req *apiGetTagsRequest) (*apiGetTagsResult, error) {
	if !checkPermission(ctx, req.Project, permGet) {
		return nil, errForbidden
	}

	fullName := req.Project + "/" + req.Repository

	var repoName string
	err := pgctx.QueryRow(ctx, `
		select name from repositories where name = $1 and namespace = $2
	`, fullName, req.Project).Scan(&repoName)
	if err != nil {
		return nil, errRepoNotFound
	}

	var items []apiTagItem
	err = pgctx.Iter(ctx, func(scan pgsql.Scanner) error {
		var it apiTagItem
		if err := scan(&it.Tag, &it.Digest, &it.CreatedAt); err != nil {
			return err
		}
		items = append(items, it)
		return nil
	}, `
		select tag, digest, created_at
		from tags
		where repository = $1
		order by created_at desc
	`, fullName)
	if err != nil {
		return nil, err
	}

	if items == nil {
		items = []apiTagItem{}
	}
	return &apiGetTagsResult{
		Name:  strings.TrimPrefix(repoName, req.Project+"/"),
		Items: items,
	}, nil
}

// getManifests

type apiGetManifestsRequest struct {
	Project    string `json:"project"`
	Repository string `json:"repository"`
}

func (r *apiGetManifestsRequest) Valid() error {
	if r.Project == "" {
		return arpc.NewError("project required")
	}
	if r.Repository == "" {
		return arpc.NewError("repository required")
	}
	return nil
}

type apiManifestItem struct {
	Digest    string    `json:"digest"`
	CreatedAt time.Time `json:"createdAt"`
}

type apiGetManifestsResult struct {
	Name  string            `json:"name"`
	Items []apiManifestItem `json:"items"`
}

func (a *App) apiGetManifests(ctx context.Context, req *apiGetManifestsRequest) (*apiGetManifestsResult, error) {
	if !checkPermission(ctx, req.Project, permGet) {
		return nil, errForbidden
	}

	fullName := req.Project + "/" + req.Repository

	var repoName string
	err := pgctx.QueryRow(ctx, `
		select name from repositories where name = $1 and namespace = $2
	`, fullName, req.Project).Scan(&repoName)
	if err != nil {
		return nil, errRepoNotFound
	}

	var items []apiManifestItem
	err = pgctx.Iter(ctx, func(scan pgsql.Scanner) error {
		var it apiManifestItem
		if err := scan(&it.Digest, &it.CreatedAt); err != nil {
			return err
		}
		items = append(items, it)
		return nil
	}, `
		select digest, created_at
		from manifests
		where repository = $1
		order by created_at desc
	`, fullName)
	if err != nil {
		return nil, err
	}

	if items == nil {
		items = []apiManifestItem{}
	}
	return &apiGetManifestsResult{
		Name:  strings.TrimPrefix(repoName, req.Project+"/"),
		Items: items,
	}, nil
}

// getProjectStorage

type apiGetProjectStorageRequest struct {
	Project string `json:"project"`
}

func (r *apiGetProjectStorageRequest) Valid() error {
	if r.Project == "" {
		return arpc.NewError("project required")
	}
	return nil
}

type apiGetProjectStorageResult struct {
	Size      int64      `json:"size"`
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`
}

func (a *App) apiGetProjectStorage(ctx context.Context, req *apiGetProjectStorageRequest) (*apiGetProjectStorageResult, error) {
	if !checkPermission(ctx, req.Project, permGet) {
		return nil, errForbidden
	}

	var size int64
	var updatedAt time.Time
	err := pgctx.QueryRow(ctx, `
		select size, updated_at
		from project_storage_usage
		where namespace = $1
	`, req.Project).Scan(&size, &updatedAt)
	if err != nil {
		// No record yet — job hasn't run or project has no data
		return &apiGetProjectStorageResult{Size: 0}, nil
	}

	return &apiGetProjectStorageResult{
		Size:      size,
		UpdatedAt: &updatedAt,
	}, nil
}

// delete

type apiDeleteRequest struct {
	Project    string `json:"project"`
	Repository string `json:"repository"`
}

func (r *apiDeleteRequest) Valid() error {
	if r.Project == "" {
		return arpc.NewError("project required")
	}
	if r.Repository == "" {
		return arpc.NewError("repository required")
	}
	return nil
}

func (a *App) apiDelete(ctx context.Context, req *apiDeleteRequest) error {
	if !checkPermission(ctx, req.Project, permPush) {
		return errForbidden
	}

	fullName := req.Project + "/" + req.Repository

	var exists bool
	if err := pgctx.QueryRow(ctx, `
		select exists (select 1 from repositories where name = $1 and namespace = $2)
	`, fullName, req.Project).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return errRepoNotFound
	}

	// Detach from the request context so the deletion runs to completion
	// even if the client disconnects or the request times out. The detached
	// context still carries pgctx DB and other values from the parent.
	dctx := context.WithoutCancel(ctx)

	// Delete all GCS objects under this repository prefix
	it := a.Bucket.Objects(dctx, &storage.Query{
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
		if err := a.Bucket.Object(attrs.Name).Delete(dctx); err != nil && !isNotFound(err) {
			return err
		}
	}

	// Delete DB records in FK dependency order
	for _, query := range []string{
		`delete from manifest_blobs where repository = $1`,
		`delete from tags        where repository = $1`,
		`delete from manifests   where repository = $1`,
		`delete from blobs       where repository = $1`,
		`delete from repositories where name = $1`,
	} {
		if _, err := pgctx.Exec(dctx, query, fullName); err != nil {
			return err
		}
	}

	return nil
}

// deleteManifest

type apiDeleteManifestRequest struct {
	Project    string `json:"project"`
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
}

func (r *apiDeleteManifestRequest) Valid() error {
	if r.Project == "" {
		return arpc.NewError("project required")
	}
	if r.Repository == "" {
		return arpc.NewError("repository required")
	}
	if r.Digest == "" {
		return arpc.NewError("digest required")
	}
	return nil
}

func (a *App) apiDeleteManifest(ctx context.Context, req *apiDeleteManifestRequest) error {
	if !checkPermission(ctx, req.Project, permPush) {
		return errForbidden
	}

	fullName := req.Project + "/" + req.Repository

	var exists bool
	if err := pgctx.QueryRow(ctx, `
		select exists (select 1 from manifests where repository = $1 and digest = $2)
	`, fullName, req.Digest).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return errManifestNotFound
	}

	// Detach from the request context so the deletion runs to completion
	// even if the client disconnects or the request times out.
	ctx = context.WithoutCancel(ctx)

	// Collect tags pointing to this manifest.
	var tags []string
	err := pgctx.Iter(ctx, func(scan pgsql.Scanner) error {
		var tag string
		if err := scan(&tag); err != nil {
			return err
		}
		tags = append(tags, tag)
		return nil
	}, `select tag from tags where repository = $1 and digest = $2`, fullName, req.Digest)
	if err != nil {
		return err
	}

	// Delete GCS objects (digest-addressed manifest + all tag-addressed manifests) in parallel.
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		obj := a.Bucket.Object(fmt.Sprintf("%s/manifests/%s", fullName, req.Digest))
		if err := obj.Delete(gctx); err != nil && !isNotFound(err) {
			return err
		}
		return nil
	})
	for _, tag := range tags {
		tag := tag
		g.Go(func() error {
			obj := a.Bucket.Object(fmt.Sprintf("%s/manifests/%s", fullName, tag))
			if err := obj.Delete(gctx); err != nil && !isNotFound(err) {
				return err
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	// Delete DB records in FK dependency order.
	for _, q := range []string{
		`delete from manifest_blobs where repository = $1 and manifest_digest = $2`,
		`delete from tags            where repository = $1 and digest         = $2`,
		`delete from manifests       where repository = $1 and digest         = $2`,
	} {
		if _, err := pgctx.Exec(ctx, q, fullName, req.Digest); err != nil {
			return err
		}
	}

	return nil
}

// untag

type apiUntagRequest struct {
	Project    string `json:"project"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
}

func (r *apiUntagRequest) Valid() error {
	if r.Project == "" {
		return arpc.NewError("project required")
	}
	if r.Repository == "" {
		return arpc.NewError("repository required")
	}
	if r.Tag == "" {
		return arpc.NewError("tag required")
	}
	return nil
}

func (a *App) apiUntag(ctx context.Context, req *apiUntagRequest) error {
	if !checkPermission(ctx, req.Project, permPush) {
		return errForbidden
	}

	fullName := req.Project + "/" + req.Repository

	var exists bool
	if err := pgctx.QueryRow(ctx, `
		select exists (select 1 from tags where repository = $1 and tag = $2)
	`, fullName, req.Tag).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return errTagNotFound
	}

	// Delete the tag-named GCS object (best-effort; ignore if already gone)
	obj := a.Bucket.Object(fmt.Sprintf("%s/manifests/%s", fullName, req.Tag))
	if err := obj.Delete(ctx); err != nil && !isNotFound(err) {
		return err
	}

	if _, err := pgctx.Exec(ctx, `
		delete from tags where repository = $1 and tag = $2
	`, fullName, req.Tag); err != nil {
		return err
	}

	return nil
}
