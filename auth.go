package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/moonrhythm/cachestore"
	"github.com/moonrhythm/sf"
)

// Overridable in tests; production points at the real API.
var (
	authEndpoint = "https://api.deploys.app/me.authorized"
	infoEndpoint = "https://api.deploys.app/me.get"
)

const (
	cacheTTL = 30 * time.Second

	permPull = "registry.pull"
	permPush = "registry.push"
	permList = "registry.list"
	permGet  = "registry.get"
)

type contextKey int

const (
	namespaceKey contextKey = iota
	authKey
	projectIDKey
)

func namespaceFromContext(ctx context.Context) string {
	v, _ := ctx.Value(namespaceKey).(string)
	return v
}

func authFromContext(ctx context.Context) string {
	v, _ := ctx.Value(authKey).(string)
	return v
}

func projectIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(projectIDKey).(string)
	return v
}

func apiAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			r = r.WithContext(context.WithValue(r.Context(), authKey, auth))
		}
		next.ServeHTTP(w, r)
	})
}

func getEmail(ctx context.Context, auth string) string {
	cacheKey := "registry|email|" + auth
	if v, ok := cachestore.Get[string](cacheKey); ok {
		return v
	}

	// Collapse concurrent /v2/ pings carrying the same token into a single
	// /me.get round-trip. The result is cached for 30s (cacheTTL); sf.Do
	// dedupe matters at the cold-cache edge and right after that entry
	// expires under load.
	email, _, _ := sf.Do(ctx, cacheKey, func(ctx context.Context) (string, error) {
		// Re-check the cache: a sibling caller may have populated it
		// while we were queued behind sf's mutex.
		if v, ok := cachestore.Get[string](cacheKey); ok {
			return v, nil
		}

		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, infoEndpoint, bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Authorization", auth)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			// Don't cache transport failures — let the next caller retry.
			return "", nil
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", nil
		}

		var res struct {
			OK     bool `json:"ok"`
			Result struct {
				Email string `json:"email"`
			} `json:"result"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil || !res.OK {
			return "", nil
		}

		cachestore.Set(cacheKey, res.Result.Email, &cachestore.SetOptions{TTL: cacheTTL})
		return res.Result.Email, nil
	})
	return email
}

type permissionResult struct {
	OK        bool
	ProjectID string
}

func checkPermissionWithID(ctx context.Context, project, permission string) permissionResult {
	auth := authFromContext(ctx)

	cacheKey := "registry|perm|" + auth + "|" + project + "|" + permission
	if v, ok := cachestore.Get[permissionResult](cacheKey); ok {
		return v
	}

	// Collapse a thundering herd of concurrent requests from the same
	// caller into a single /me.authorized round-trip. The result is
	// cached for 30s (cacheTTL); sf.Do dedupe matters at the cold-cache
	// edge and right after that entry expires under load.
	result, _, _ := sf.Do(ctx, cacheKey, func(ctx context.Context) (permissionResult, error) {
		// Re-check the cache: a sibling caller may have populated it
		// while we were queued behind sf's mutex.
		if v, ok := cachestore.Get[permissionResult](cacheKey); ok {
			return v, nil
		}

		body, _ := json.Marshal(map[string]any{
			"project":     project,
			"permissions": []string{permission},
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, authEndpoint, bytes.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			// Don't cache transport failures — let the next caller retry.
			return permissionResult{}, nil
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return permissionResult{}, nil
		}

		var res struct {
			OK     bool `json:"ok"`
			Result struct {
				Authorized bool `json:"authorized"`
				Project    struct {
					ID             string `json:"id"`
					BillingAccount struct {
						Active bool `json:"active"`
					} `json:"billingAccount"`
				} `json:"project"`
			} `json:"result"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return permissionResult{}, nil
		}

		var result permissionResult
		if res.OK && res.Result.Authorized && res.Result.Project.BillingAccount.Active {
			result = permissionResult{
				OK:        true,
				ProjectID: res.Result.Project.ID,
			}
		}
		cachestore.Set(cacheKey, result, &cachestore.SetOptions{TTL: cacheTTL})
		return result, nil
	})
	return result
}

func checkPermission(ctx context.Context, project, permission string) bool {
	return checkPermissionWithID(ctx, project, permission).OK
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")

		ctx := r.Context()
		if auth != "" {
			ctx = context.WithValue(ctx, authKey, auth)
			r = r.WithContext(ctx)
		}

		path := r.URL.Path
		if path == "/v2/" {
			if auth != "" && getEmail(ctx, auth) == "" {
				registryUnauthorized(w, r)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		project := extractProject(path)
		if project == "" {
			registryUnauthorized(w, r)
			return
		}

		ctx = context.WithValue(ctx, namespaceKey, project)
		r = r.WithContext(ctx)

		if res := checkPermissionWithID(ctx, project, permPush); res.OK {
			ctx = context.WithValue(ctx, projectIDKey, res.ProjectID)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		if isPushRequest(r.Method) {
			registryUnauthorized(w, r)
			return
		}

		if res := checkPermissionWithID(ctx, project, permPull); res.OK {
			ctx = context.WithValue(ctx, projectIDKey, res.ProjectID)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		registryUnauthorized(w, r)
	})
}

func registryUnauthorized(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", "basic realm="+r.URL.String())
	registryError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
}

func isPushRequest(method string) bool {
	return method != http.MethodGet && method != http.MethodHead
}

func extractProject(path string) string {
	const prefix = "/v2/"
	if len(path) <= len(prefix) {
		return ""
	}
	rest := path[len(prefix):]
	for i, c := range rest {
		if c == '/' {
			return rest[:i]
		}
	}
	return ""
}
