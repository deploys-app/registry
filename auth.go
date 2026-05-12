package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/moonrhythm/cachestore"
)

const (
	authEndpoint = "https://api.deploys.app/me.authorized"
	infoEndpoint = "https://api.deploys.app/me.get"
	cacheTTL     = 30 * time.Second

	permPull = "registry.pull"
	permPush = "registry.push"
	permList = "registry.list"
	permGet  = "registry.get"
)

type contextKey int

const (
	namespaceKey contextKey = iota
	authKey
)

func namespaceFromContext(ctx context.Context) string {
	v, _ := ctx.Value(namespaceKey).(string)
	return v
}

func authFromContext(ctx context.Context) string {
	v, _ := ctx.Value(authKey).(string)
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

func getEmail(auth string) string {
	cacheKey := "registry|email|" + auth
	if v, ok := cachestore.Get[string](cacheKey); ok {
		return v
	}

	req, _ := http.NewRequest(http.MethodPost, infoEndpoint, bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var res struct {
		OK     bool `json:"ok"`
		Result struct {
			Email string `json:"email"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil || !res.OK {
		return ""
	}

	cachestore.Set(cacheKey, res.Result.Email, &cachestore.SetOptions{TTL: cacheTTL})
	return res.Result.Email
}

func checkPermission(ctx context.Context, project, permission string) bool {
	auth := authFromContext(ctx)

	cacheKey := "registry|perm|" + auth + "|" + project + "|" + permission
	if v, ok := cachestore.Get[bool](cacheKey); ok {
		return v
	}

	body, _ := json.Marshal(map[string]any{
		"project":     project,
		"permissions": []string{permission},
	})
	req, _ := http.NewRequest(http.MethodPost, authEndpoint, bytes.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}

	var res struct {
		OK     bool `json:"ok"`
		Result struct {
			Authorized bool `json:"authorized"`
			Project    struct {
				BillingAccount struct {
					Active bool `json:"active"`
				} `json:"billingAccount"`
			} `json:"project"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return false
	}

	ok := res.OK && res.Result.Authorized && res.Result.Project.BillingAccount.Active
	cachestore.Set(cacheKey, ok, &cachestore.SetOptions{TTL: cacheTTL})
	return ok
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
			if auth == "" || getEmail(auth) == "" {
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

		if checkPermission(ctx, project, permPush) {
			next.ServeHTTP(w, r)
			return
		}

		if isPushRequest(r.Method) {
			registryUnauthorized(w, r)
			return
		}

		if checkPermission(ctx, project, permPull) {
			next.ServeHTTP(w, r)
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
