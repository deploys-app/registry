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

## Migration from Cloudflare D1

A one-time migration script is provided to import existing data from Cloudflare D1 into PostgreSQL.

```sh
CLOUDFLARE_API_TOKEN=... \
CLOUDFLARE_ACCOUNT_ID=... \
DB_URL=postgres://... \
go run ./migrate/
```

| Variable | Required | Default | Description |
|---|---|---|---|
| `CLOUDFLARE_API_TOKEN` | yes | — | Cloudflare API token |
| `CLOUDFLARE_ACCOUNT_ID` | yes | — | Cloudflare account ID |
| `DB_URL` | yes | — | PostgreSQL connection string |
| `D1_DATABASE_ID` | no | `67b907e7-9d0d-4846-851e-8e7da80acbad` | D1 database ID |

The script migrates all four tables (`repositories`, `manifests`, `tags`, `blobs`) in dependency order, in batches of 1000 rows. It is safe to re-run — rows that already exist are skipped.
