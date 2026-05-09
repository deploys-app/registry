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
