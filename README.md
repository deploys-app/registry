# registry

Docker container registry service for [Deploys.app](https://deploys.app), implementing the [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec/blob/main/spec.md).

## Architecture

- **Storage**: Google Cloud Storage (blobs and manifests)
- **Database**: PostgreSQL (repository, manifest, tag, and blob metadata)
- **Auth**: Delegated to the Deploys.app API (`api.deploys.app`)

## Configuration

All configuration is via environment variables.

| Variable | Required | Default | Description |
|---|---|---|---|
| `DB_URL` | yes | — | PostgreSQL connection string |
| `BUCKET_NAME` | yes | — | GCS bucket name |
| `PORT` | no | `8080` | HTTP listen port |
| `LOG_LEVEL` | no | `INFO` | Log level (`DEBUG`, `INFO`, `WARN`, `ERROR`) |
| `INTERNAL_SECRET` | no | — | Bearer token for `/internal/*` endpoints |

The service authenticates with Google Cloud using [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials).

## Running

```sh
DB_URL=postgres://user:pass@host/db \
BUCKET_NAME=my-registry-bucket \
go run .
```

## Docker

```sh
docker build -t registry .
docker run -e DB_URL=... -e BUCKET_NAME=... registry
```

## Database

Apply the schema before first run:

```sh
psql $DB_URL -f schema.sql
```

### Tables

| Table | Description |
|---|---|
| `repositories` | Repository metadata (name, namespace, created_at) |
| `manifests` | OCI manifests per repository |
| `tags` | Tag → manifest digest mappings |
| `blobs` | Blob metadata including size |
| `manifest_blobs` | Manifest → blob references (rebuilt by `indexManifests`) |
| `project_storage_usage` | Pre-calculated total blob storage per project namespace (updated by `calculateProjectStorage`) |

## API

### Registry (`/v2/`)

Implements the OCI Distribution Spec v1. Compatible with `docker`, `crane`, `skopeo`, and any standard OCI client.

Authentication uses HTTP Basic Auth. Credentials are forwarded to the Deploys.app API to verify project permissions:

- `registry.pull` — required for `GET`/`HEAD`
- `registry.push` — required for `POST`/`PUT`/`PATCH`/`DELETE`

### Management (`/api/`)

All management endpoints accept `POST` with `Content-Type: application/json` and return `{"ok": true, "result": {...}}` or `{"ok": false, "error": {"message": "..."}}`.

#### `POST /api/list`

List repositories in a project namespace.

```json
{ "project": "my-project" }
```

Requires `registry.list` permission.

#### `POST /api/get`

Get repository info and total blob storage size.

```json
{ "project": "my-project", "repository": "my-image" }
```

Requires `registry.get` permission.

#### `POST /api/getTags`

List tags for a repository with their digest and creation time.

```json
{ "project": "my-project", "repository": "my-image" }
```

Requires `registry.get` permission.

#### `POST /api/getManifests`

List manifests for a repository with their digest and creation time.

```json
{ "project": "my-project", "repository": "my-image" }
```

Requires `registry.get` permission.

#### `POST /api/getProjectStorage`

Get the pre-calculated total blob storage used across all repositories in a project. The value is updated once per day by the `calculateProjectStorage` scheduler job. Returns `size: 0` with no `updatedAt` if the job has not run yet.

```json
{ "project": "my-project" }
```

Response:

```json
{ "size": 1073741824, "updatedAt": "2024-01-15T03:00:00Z" }
```

Requires `registry.get` permission.

#### `POST /api/deleteManifest`

Delete a single manifest by digest, including all tags that point to it and their GCS objects. Blobs referenced by the manifest are **not** deleted immediately — they are cleaned up by the blob GC.

```json
{ "project": "my-project", "repository": "my-image", "digest": "sha256:abc123..." }
```

Requires `registry.push` permission.

#### `POST /api/delete`

Delete a repository and all its data — manifests, tags, blobs, and the corresponding GCS objects. The operation continues to completion even if the client disconnects or the request times out.

```json
{ "project": "my-project", "repository": "my-image" }
```

Requires `registry.push` permission.

## Internal API

### `POST /internal/indexManifests`

Reads every manifest that has no `manifest_blobs` rows yet, fetches its content from GCS, and records which blobs it references. Runs as part of `POST /internal/runAll`.

Protected by `Authorization: Bearer <INTERNAL_SECRET>`. If `INTERNAL_SECRET` is not set the check is skipped (local dev only).

Returns `204 No Content` on success.

To trigger manually:

```sh
curl -X POST https://registry.deploys.app/internal/indexManifests \
  -H "Authorization: Bearer <INTERNAL_SECRET>"
```

### `POST /internal/runBlobGC`

Deletes blobs that are not referenced by any manifest and are older than 1 day. The 1-day grace period covers blobs that have been uploaded but whose manifest push is still in flight. Runs as part of `POST /internal/runAll`.

Returns `204 No Content` on success. Protected by the same `INTERNAL_SECRET` bearer token.

To trigger manually:

```sh
curl -X POST https://registry.deploys.app/internal/runBlobGC \
  -H "Authorization: Bearer <INTERNAL_SECRET>"
```

### `POST /internal/calculateProjectStorage`

Calculates the total blob storage used by each project namespace and stores the result in the `project_storage_usage` table. Results are served via `POST /api/getProjectStorage`.

Because the `blobs` table can be very large, this is designed to run once per day rather than on every API request.

Returns `204 No Content` on success. Protected by the same `INTERNAL_SECRET` bearer token.

To trigger manually:

```sh
curl -X POST https://registry.deploys.app/internal/calculateProjectStorage \
  -H "Authorization: Bearer <INTERNAL_SECRET>"
```

### `POST /internal/runAll`

Runs all scheduled jobs sequentially in a single HTTP call:

1. `indexManifests`
2. `runBlobGC`
3. `calculateProjectStorage`

Use this as the single Cloud Scheduler target so only one scheduler job is needed. If any step fails the endpoint returns `500` immediately (remaining steps are skipped) and the error is logged.

Returns `204 No Content` on success. Protected by the same `INTERNAL_SECRET` bearer token.

#### Cloud Scheduler setup

Replace the individual per-job scheduler entries with a single job targeting `/internal/runAll`:

```sh
gcloud scheduler jobs create http registry-run-all \
  --location=asia-southeast1 \
  --schedule="0 2 * * *" \
  --uri="https://registry.deploys.app/internal/runAll" \
  --http-method=POST \
  --headers="Authorization=Bearer <INTERNAL_SECRET>" \
  --attempt-deadline=30m \
  --time-zone="UTC"
```

To update the schedule or secret on an existing job:

```sh
gcloud scheduler jobs update http registry-run-all \
  --location=asia-southeast1 \
  --schedule="0 2 * * *" \
  --headers="Authorization=Bearer <INTERNAL_SECRET>"
```

To trigger immediately (e.g. after initial deploy):

```sh
gcloud scheduler jobs run registry-run-all \
  --location=asia-southeast1
```

## Migration

### Cloudflare D1 → PostgreSQL (`migrate/d1topg`)

Imports existing metadata from Cloudflare D1 into PostgreSQL.

```sh
CLOUDFLARE_API_TOKEN=... \
CLOUDFLARE_ACCOUNT_ID=... \
DB_URL=postgres://... \
go run ./migrate/d1topg/
```

| Variable | Required | Default | Description |
|---|---|---|---|
| `CLOUDFLARE_API_TOKEN` | yes | — | Cloudflare API token |
| `CLOUDFLARE_ACCOUNT_ID` | yes | — | Cloudflare account ID |
| `DB_URL` | yes | — | PostgreSQL connection string |
| `D1_DATABASE_ID` | no | `67b907e7-9d0d-4846-851e-8e7da80acbad` | D1 database ID |

Migrates all four tables (`repositories`, `manifests`, `tags`, `blobs`) in dependency order, in batches of 1000 rows. Safe to re-run — rows that already exist are skipped.

### Cloudflare R2 → GCS (`migrate/r2togcs`)

Copies all objects from Cloudflare R2 to Google Cloud Storage, preserving content-type and `docker-content-digest` metadata. For tag-addressed manifests the SHA256 digest is computed on the fly. Temporary upload objects (`_uploads/`) are skipped.

```sh
R2_ACCOUNT_ID=... \
R2_ACCESS_KEY_ID=... \
R2_SECRET_ACCESS_KEY=... \
BUCKET_NAME=my-gcs-bucket \
go run ./migrate/r2togcs/
```

| Variable | Required | Default | Description |
|---|---|---|---|
| `R2_ACCOUNT_ID` | yes | — | Cloudflare account ID |
| `R2_ACCESS_KEY_ID` | yes | — | R2 access key ID |
| `R2_SECRET_ACCESS_KEY` | yes | — | R2 secret access key |
| `BUCKET_NAME` | yes | — | GCS destination bucket name |
| `R2_BUCKET` | no | `deploys-registry` | R2 source bucket name |
| `WORKERS` | no | `8` | Number of parallel copy workers |

Safe to re-run — objects already present in GCS are skipped.
