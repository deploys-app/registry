package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A single mock server is started lazily and serves every auth test. It
// routes by request path (/me.authorized vs /me.get) and by Authorization
// header so parallel tests don't race over the package-level endpoint vars
// or trample each other's cachestore entries (cache keys include the token).
var (
	authMockOnce sync.Once
	authMockMap  sync.Map // token -> http.HandlerFunc
)

func setupAuthMock() {
	authMockOnce.Do(func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h, ok := authMockMap.Load(r.Header.Get("Authorization")); ok {
				h.(http.HandlerFunc)(w, r)
				return
			}
			http.Error(w, "no mock registered for token", http.StatusNotFound)
		}))
		authEndpoint = srv.URL + "/me.authorized"
		infoEndpoint = srv.URL + "/me.get"
	})
}

func registerAuthMock(t *testing.T, token string, h http.HandlerFunc) {
	t.Helper()
	setupAuthMock()
	authMockMap.Store(token, h)
	t.Cleanup(func() { authMockMap.Delete(token) })
}

// jsonAuthorized responds with the standard /me.authorized envelope.
func jsonAuthorized(authorized, billingActive bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"result": map[string]any{
				"authorized": authorized,
				"project": map[string]any{
					"id": "proj-123",
					"billingAccount": map[string]any{
						"active": billingActive,
					},
				},
			},
		})
	}
}

// jsonEmail responds with the standard /me.get envelope.
func jsonEmail(email string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"ok":     true,
			"result": map[string]any{"email": email},
		})
	}
}

func ctxWithAuth(token string) context.Context {
	return context.WithValue(context.Background(), authKey, token)
}

func TestCheckPermission_Authorized(t *testing.T) {
	t.Parallel()
	token := "Bearer " + t.Name()
	registerAuthMock(t, token, jsonAuthorized(true, true))

	res := checkPermissionWithID(ctxWithAuth(token), "myproject", permPull)
	if !res.OK {
		t.Fatal("expected authorized")
	}
	if res.ProjectID != "proj-123" {
		t.Errorf("project ID = %q, want proj-123", res.ProjectID)
	}
}

func TestCheckPermission_NotAuthorized(t *testing.T) {
	t.Parallel()
	token := "Bearer " + t.Name()
	registerAuthMock(t, token, jsonAuthorized(false, true))

	if checkPermissionWithID(ctxWithAuth(token), "myproject", permPull).OK {
		t.Error("expected unauthorized when API returns authorized=false")
	}
}

func TestCheckPermission_BillingInactive(t *testing.T) {
	t.Parallel()
	token := "Bearer " + t.Name()
	registerAuthMock(t, token, jsonAuthorized(true, false))

	if checkPermissionWithID(ctxWithAuth(token), "myproject", permPull).OK {
		t.Error("expected unauthorized when billing is inactive")
	}
}

func TestCheckPermission_API500(t *testing.T) {
	t.Parallel()
	token := "Bearer " + t.Name()
	registerAuthMock(t, token, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	if checkPermissionWithID(ctxWithAuth(token), "myproject", permPull).OK {
		t.Error("expected unauthorized when auth API returns 500")
	}
}

func TestCheckPermission_InvalidJSON(t *testing.T) {
	t.Parallel()
	token := "Bearer " + t.Name()
	registerAuthMock(t, token, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	})

	if checkPermissionWithID(ctxWithAuth(token), "myproject", permPull).OK {
		t.Error("expected unauthorized when auth API returns invalid JSON")
	}
}

func TestCheckPermission_CachesResult(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	token := "Bearer " + t.Name()
	registerAuthMock(t, token, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		jsonAuthorized(true, true)(w, r)
	})

	ctx := ctxWithAuth(token)
	checkPermissionWithID(ctx, "myproject", permPull)
	checkPermissionWithID(ctx, "myproject", permPull)

	if got := calls.Load(); got != 1 {
		t.Errorf("auth API called %d times, want 1 (should be cached)", got)
	}
}

func TestCheckPermission_CacheKeyDistinguishesPermissions(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	token := "Bearer " + t.Name()
	registerAuthMock(t, token, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		jsonAuthorized(true, true)(w, r)
	})

	ctx := ctxWithAuth(token)
	checkPermissionWithID(ctx, "myproject", permPush)
	checkPermissionWithID(ctx, "myproject", permPull)
	checkPermissionWithID(ctx, "myproject", permPush) // cached
	checkPermissionWithID(ctx, "myproject", permPull) // cached

	if got := calls.Load(); got != 2 {
		t.Errorf("auth API called %d times, want 2 (one per distinct permission)", got)
	}
}

func TestCheckPermission_SingleflightCollapsesConcurrentCalls(t *testing.T) {
	// 50 goroutines race on a cold-cache (auth, project, permission)
	// triple. sf.Do must collapse them into a single /me.authorized
	// round-trip — otherwise a burst of concurrent pulls/pushes from one
	// caller (e.g. a parallel CI matrix pulling the same image) hammers
	// the deploys.app API on every cache-miss edge.
	t.Parallel()
	var calls atomic.Int64
	token := "Bearer " + t.Name()
	registerAuthMock(t, token, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		// A short sleep widens the singleflight window so the test
		// reliably catches a regression where dedupe is broken.
		time.Sleep(50 * time.Millisecond)
		jsonAuthorized(true, true)(w, r)
	})

	const N = 50
	ctx := ctxWithAuth(token)
	results := make([]permissionResult, N)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = checkPermissionWithID(ctx, "sfproject", permPull)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, r := range results {
		if !r.OK {
			t.Errorf("results[%d] not authorized", i)
		}
	}
	if got := calls.Load(); got >= N {
		t.Errorf("auth API called %d times, want <%d (sf should have collapsed the herd)", got, N)
	}
}

func TestGetEmail_ReturnsEmail(t *testing.T) {
	t.Parallel()
	token := "Bearer " + t.Name()
	registerAuthMock(t, token, jsonEmail("user@example.com"))

	if got := getEmail(context.Background(), token); got != "user@example.com" {
		t.Errorf("email = %q, want user@example.com", got)
	}
}

func TestGetEmail_CachesResult(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	token := "Bearer " + t.Name()
	registerAuthMock(t, token, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		jsonEmail("user@example.com")(w, r)
	})

	getEmail(context.Background(), token)
	getEmail(context.Background(), token)

	if got := calls.Load(); got != 1 {
		t.Errorf("info API called %d times, want 1 (should be cached)", got)
	}
}

func TestGetEmail_SingleflightCollapsesConcurrentCalls(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	token := "Bearer " + t.Name()
	registerAuthMock(t, token, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		jsonEmail("user@example.com")(w, r)
	})

	const N = 50
	emails := make([]string, N)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			emails[idx] = getEmail(context.Background(), token)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, e := range emails {
		if e != "user@example.com" {
			t.Errorf("emails[%d] = %q, want user@example.com", i, e)
		}
	}
	if got := calls.Load(); got >= N {
		t.Errorf("info API called %d times, want <%d (sf should have collapsed the herd)", got, N)
	}
}
