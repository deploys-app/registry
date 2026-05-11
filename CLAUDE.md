# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
# Build
go build ./...

# Run locally (requires a real PostgreSQL and GCS bucket)
DB_URL=postgres://user:pass@host/db BUCKET_NAME=my-bucket go run .

# Apply database schema (first run or after schema changes)
psql $DB_URL -f schema.sql
```

There are no tests in this repository. CI only builds and pushes a Docker image on push to `main`.

## Architecture

Single-binary Go service (`package main`) — all files compile together with no internal packages.

### File map

| File | Responsibility |
|---|---|
| `main.go` | Server bootstrap: connects DB + GCS, wires middleware, registers all HTTP routes |
| `registry.go` | OCI Distribution Spec v1 implementation (`/v2/` routes) including chunked blob upload via GCS compose |
| `api.go` | Management API (`/api/` routes) using arpc |
| `auth.go` | Auth middleware + `checkPermission` / `getEmail` helpers that delegate to `api.deploys.app` with 30 s in-memory caching |
| `gc.go` | `runBlobGC` — deletes unreferenced blobs older than 1 day |
| `storage_usage.go` | `calculateProjectStorage` — aggregates blob sizes per project namespace |
| `errors.go` | Shared `arpc.NewError` values (`errForbidden`, `errRepoNotFound`, etc.) |
| `schema.sql` | PostgreSQL schema (apply manually; no migration tool) |

### Request flow

```
HTTP → parapet (healthz, logger) → pgctx middleware (injects *sql.DB into ctx)
         ├── /v2/   → authMiddleware → registryHandler (OCI spec)
         ├── /api/  → apiAuthMiddleware → arpc router (management API)
         └── /internal/  → internalAuth (Bearer token) → job handlers
```

### Key design decisions

**arpc response envelope** — all `/api/` endpoints return `{"ok": true, "result": {...}}` on success or `{"ok": false, "error": {"message": "..."}}` on failure. Handler functions return `(*Result, error)` for endpoints with a body, or just `error` for void endpoints.

**Repository naming** — the `repositories.name` column stores the full `{namespace}/{repo}` string. `namespace` is a redundant denormalized column used for project-scoped queries. Blobs and manifests reference `repository` using the full name.

**Blob upload** — OCI chunked uploads land as numbered GCS objects (`_uploads/{uuid}/{n}`) then are composed into the final blob path. GCS limits compose to 32 sources, so the code stages multiple compose passes for large uploads.

**Scheduled jobs** — three jobs exist: `indexManifests`, `runBlobGC`, `calculateProjectStorage`. They are triggered via `POST /internal/runAll` (single Cloud Scheduler target) or individually via their own `/internal/*` endpoints. All internal endpoints are protected by `INTERNAL_SECRET` bearer token (skipped if unset — local dev only).

**Auth caching** — `checkPermission` and `getEmail` cache results in `cachestore` (in-process, 30 s TTL) to avoid hammering `api.deploys.app` on every request.

**Context propagation** — long-running delete operations call `context.WithoutCancel(ctx)` so the deletion completes even if the HTTP client disconnects. The detached context still carries the pgctx DB connection.
