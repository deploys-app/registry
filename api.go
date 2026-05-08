package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/acoshift/pgsql/pgctx"
)

func (a *App) apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiProtocolError(w, http.StatusBadRequest, "method not allowed")
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		apiProtocolError(w, http.StatusBadRequest, "unsupported content type")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api")
	switch path {
	case "/list":
		a.apiList(w, r)
	case "/get":
		a.apiGet(w, r)
	case "/getTags":
		a.apiGetTags(w, r)
	case "/getManifests":
		a.apiGetManifests(w, r)
	default:
		apiProtocolError(w, http.StatusBadRequest, "not found")
	}
}

func (a *App) apiList(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Project string `json:"project"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Project == "" {
		apiError(w, "project required")
		return
	}

	auth := r.Header.Get("Authorization")
	if !checkPermission(auth, req.Project, permList) {
		apiError(w, "iam: forbidden")
		return
	}

	ctx := r.Context()
	rows, err := pgctx.Query(ctx, `
		select name, created_at
		from repositories
		where namespace = $1
		order by name
	`, req.Project)
	if err != nil {
		apiError(w, "internal error")
		return
	}
	defer rows.Close()

	type item struct {
		Name      string `json:"name"`
		CreatedAt string `json:"createdAt"`
	}
	items := []item{}
	prefix := req.Project + "/"
	for rows.Next() {
		var name string
		var createdAt time.Time
		if err := rows.Scan(&name, &createdAt); err != nil {
			continue
		}
		items = append(items, item{
			Name:      strings.TrimPrefix(name, prefix),
			CreatedAt: formatTime(createdAt),
		})
	}

	apiOK(w, map[string]any{"items": items})
}

func (a *App) apiGet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Project    string `json:"project"`
		Repository string `json:"repository"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Project == "" {
		apiError(w, "project required")
		return
	}
	if req.Repository == "" {
		apiError(w, "repository required")
		return
	}

	auth := r.Header.Get("Authorization")
	if !checkPermission(auth, req.Project, permGet) {
		apiError(w, "iam: forbidden")
		return
	}

	ctx := r.Context()
	fullName := req.Project + "/" + req.Repository

	var name string
	var createdAt time.Time
	err := pgctx.QueryRow(ctx, `
		select name, created_at
		from repositories
		where name = $1 and namespace = $2
	`, fullName, req.Project).Scan(&name, &createdAt)
	if err != nil {
		apiError(w, "repository not found")
		return
	}

	var size *int64
	pgctx.QueryRow(ctx, `
		select sum(size)
		from blobs
		where repository = $1
	`, fullName).Scan(&size)

	apiOK(w, map[string]any{
		"name":      strings.TrimPrefix(name, req.Project+"/"),
		"size":      size,
		"createdAt": formatTime(createdAt),
	})
}

func (a *App) apiGetTags(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Project    string `json:"project"`
		Repository string `json:"repository"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Project == "" {
		apiError(w, "project required")
		return
	}
	if req.Repository == "" {
		apiError(w, "repository required")
		return
	}

	auth := r.Header.Get("Authorization")
	if !checkPermission(auth, req.Project, permGet) {
		apiError(w, "iam: forbidden")
		return
	}

	ctx := r.Context()
	fullName := req.Project + "/" + req.Repository

	var repoName string
	var repoCreatedAt time.Time
	err := pgctx.QueryRow(ctx, `
		select name, created_at
		from repositories
		where name = $1 and namespace = $2
	`, fullName, req.Project).Scan(&repoName, &repoCreatedAt)
	if err != nil {
		apiError(w, "repository not found")
		return
	}

	rows, err := pgctx.Query(ctx, `
		select tag, digest, created_at
		from tags
		where repository = $1
		order by created_at desc
	`, fullName)
	if err != nil {
		apiError(w, "internal error")
		return
	}
	defer rows.Close()

	type item struct {
		Tag       string `json:"tag"`
		Digest    string `json:"digest"`
		CreatedAt string `json:"createdAt"`
	}
	items := []item{}
	for rows.Next() {
		var it item
		var createdAt time.Time
		if err := rows.Scan(&it.Tag, &it.Digest, &createdAt); err != nil {
			continue
		}
		it.CreatedAt = formatTime(createdAt)
		items = append(items, it)
	}

	apiOK(w, map[string]any{
		"name":  strings.TrimPrefix(repoName, req.Project+"/"),
		"items": items,
	})
}

func (a *App) apiGetManifests(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Project    string `json:"project"`
		Repository string `json:"repository"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Project == "" {
		apiError(w, "project required")
		return
	}
	if req.Repository == "" {
		apiError(w, "repository required")
		return
	}

	auth := r.Header.Get("Authorization")
	if !checkPermission(auth, req.Project, permGet) {
		apiError(w, "iam: forbidden")
		return
	}

	ctx := r.Context()
	fullName := req.Project + "/" + req.Repository

	var repoName string
	var repoCreatedAt time.Time
	err := pgctx.QueryRow(ctx, `
		select name, created_at
		from repositories
		where name = $1 and namespace = $2
	`, fullName, req.Project).Scan(&repoName, &repoCreatedAt)
	if err != nil {
		apiError(w, "repository not found")
		return
	}

	rows, err := pgctx.Query(ctx, `
		select digest, created_at
		from manifests
		where repository = $1
		order by created_at desc
	`, fullName)
	if err != nil {
		apiError(w, "internal error")
		return
	}
	defer rows.Close()

	type item struct {
		Digest    string `json:"digest"`
		CreatedAt string `json:"createdAt"`
	}
	items := []item{}
	for rows.Next() {
		var it item
		var createdAt time.Time
		if err := rows.Scan(&it.Digest, &createdAt); err != nil {
			continue
		}
		it.CreatedAt = formatTime(createdAt)
		items = append(items, it)
	}

	apiOK(w, map[string]any{
		"name":  strings.TrimPrefix(repoName, req.Project+"/"),
		"items": items,
	})
}

func apiOK(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
}

func apiError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"ok":    false,
		"error": map[string]any{"message": message},
	})
}

func apiProtocolError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"ok":    false,
		"error": map[string]any{"message": message},
	})
}

func formatTime(t time.Time) string {
	s := t.UTC().Format(time.RFC3339)
	// trim sub-second
	if i := strings.IndexByte(s, '.'); i >= 0 {
		s = s[:i] + "Z"
	}
	return s
}
