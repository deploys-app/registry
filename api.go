package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/acoshift/arpc/v2"
	"github.com/acoshift/pgsql"
	"github.com/acoshift/pgsql/pgctx"
)

func (a *App) mountAPI(mux *http.ServeMux) {
	m := arpc.New()
	mux.Handle("/api/list", m.Handler(a.apiList))
	mux.Handle("/api/get", m.Handler(a.apiGet))
	mux.Handle("/api/getTags", m.Handler(a.apiGetTags))
	mux.Handle("/api/getManifests", m.Handler(a.apiGetManifests))
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

func (a *App) apiList(ctx context.Context, r *http.Request, req *apiListRequest) (*apiListResult, error) {
	if !checkPermission(r.Header.Get("Authorization"), req.Project, permList) {
		return nil, arpc.NewError("iam: forbidden")
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
	Size      *int64    `json:"size"`
	CreatedAt time.Time `json:"createdAt"`
}

func (a *App) apiGet(ctx context.Context, r *http.Request, req *apiGetRequest) (*apiGetResult, error) {
	if !checkPermission(r.Header.Get("Authorization"), req.Project, permGet) {
		return nil, arpc.NewError("iam: forbidden")
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
		return nil, arpc.NewError("repository not found")
	}

	var size *int64
	pgctx.QueryRow(ctx, `
		select sum(size) from blobs where repository = $1
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

func (a *App) apiGetTags(ctx context.Context, r *http.Request, req *apiGetTagsRequest) (*apiGetTagsResult, error) {
	if !checkPermission(r.Header.Get("Authorization"), req.Project, permGet) {
		return nil, arpc.NewError("iam: forbidden")
	}

	fullName := req.Project + "/" + req.Repository

	var repoName string
	err := pgctx.QueryRow(ctx, `
		select name from repositories where name = $1 and namespace = $2
	`, fullName, req.Project).Scan(&repoName)
	if err != nil {
		return nil, arpc.NewError("repository not found")
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

func (a *App) apiGetManifests(ctx context.Context, r *http.Request, req *apiGetManifestsRequest) (*apiGetManifestsResult, error) {
	if !checkPermission(r.Header.Get("Authorization"), req.Project, permGet) {
		return nil, arpc.NewError("iam: forbidden")
	}

	fullName := req.Project + "/" + req.Repository

	var repoName string
	err := pgctx.QueryRow(ctx, `
		select name from repositories where name = $1 and namespace = $2
	`, fullName, req.Project).Scan(&repoName)
	if err != nil {
		return nil, arpc.NewError("repository not found")
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
