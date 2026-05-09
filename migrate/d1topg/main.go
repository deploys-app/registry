// migrate migrates data from Cloudflare D1 to PostgreSQL.
//
// Required env vars:
//
//	CLOUDFLARE_API_TOKEN  - Cloudflare API token
//	CLOUDFLARE_ACCOUNT_ID - Cloudflare account ID
//	D1_DATABASE_ID        - D1 database ID (default: 67b907e7-9d0d-4846-851e-8e7da80acbad)
//	DB_URL                - PostgreSQL connection string
package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"
)

const (
	defaultD1DatabaseID = "67b907e7-9d0d-4846-851e-8e7da80acbad"
	pageSize            = 1000
)

func main() {
	token := mustEnv("CLOUDFLARE_API_TOKEN")
	accountID := mustEnv("CLOUDFLARE_ACCOUNT_ID")
	dbURL := mustEnv("DB_URL")
	d1ID := envDefault("D1_DATABASE_ID", defaultD1DatabaseID)

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		slog.Error("open postgres", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		slog.Error("ping postgres", "error", err)
		os.Exit(1)
	}

	d1 := &d1Client{
		accountID:  accountID,
		databaseID: d1ID,
		token:      token,
		http:       &http.Client{Timeout: 60 * time.Second},
	}

	ctx := context.Background()

	if err := migrateRepositories(ctx, d1, db); err != nil {
		slog.Error("migrate repositories", "error", err)
		os.Exit(1)
	}
	if err := migrateManifests(ctx, d1, db); err != nil {
		slog.Error("migrate manifests", "error", err)
		os.Exit(1)
	}
	if err := migrateTags(ctx, d1, db); err != nil {
		slog.Error("migrate tags", "error", err)
		os.Exit(1)
	}
	if err := migrateBlobs(ctx, d1, db); err != nil {
		slog.Error("migrate blobs", "error", err)
		os.Exit(1)
	}

	slog.Info("migration complete")
}

func migrateRepositories(ctx context.Context, d1 *d1Client, db *sql.DB) error {
	slog.Info("migrating repositories")
	total := 0
	for offset := 0; ; offset += pageSize {
		rows, err := d1.query(ctx, fmt.Sprintf(`
			select name, namespace, created_at
			from repositories
			order by name
			limit %d offset %d
		`, pageSize, offset))
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			break
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, row := range rows {
			name := str(row["name"])
			namespace := str(row["namespace"])
			createdAt := parseTime(row["created_at"])
			_, err := tx.ExecContext(ctx, `
				insert into repositories (name, namespace, created_at)
				values ($1, $2, $3)
				on conflict do nothing
			`, name, namespace, createdAt)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("insert repository %s: %w", name, err)
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		total += len(rows)
		slog.Info("repositories", "count", total)
		if len(rows) < pageSize {
			break
		}
	}
	slog.Info("repositories done", "total", total)
	return nil
}

func migrateManifests(ctx context.Context, d1 *d1Client, db *sql.DB) error {
	slog.Info("migrating manifests")
	total := 0
	for offset := 0; ; offset += pageSize {
		rows, err := d1.query(ctx, fmt.Sprintf(`
			select repository, digest, created_at, updated_at
			from manifests
			order by repository, digest
			limit %d offset %d
		`, pageSize, offset))
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			break
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, row := range rows {
			repo := str(row["repository"])
			digest := str(row["digest"])
			createdAt := parseTime(row["created_at"])
			updatedAt := parseTime(row["updated_at"])
			_, err := tx.ExecContext(ctx, `
				insert into manifests (repository, digest, created_at, updated_at)
				values ($1, $2, $3, $4)
				on conflict do nothing
			`, repo, digest, createdAt, updatedAt)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("insert manifest %s@%s: %w", repo, digest, err)
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		total += len(rows)
		slog.Info("manifests", "count", total)
		if len(rows) < pageSize {
			break
		}
	}
	slog.Info("manifests done", "total", total)
	return nil
}

func migrateTags(ctx context.Context, d1 *d1Client, db *sql.DB) error {
	slog.Info("migrating tags")
	total := 0
	for offset := 0; ; offset += pageSize {
		rows, err := d1.query(ctx, fmt.Sprintf(`
			select repository, tag, digest, created_at
			from tags
			order by repository, tag
			limit %d offset %d
		`, pageSize, offset))
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			break
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, row := range rows {
			repo := str(row["repository"])
			tag := str(row["tag"])
			digest := str(row["digest"])
			createdAt := parseTime(row["created_at"])
			_, err := tx.ExecContext(ctx, `
				insert into tags (repository, tag, digest, created_at)
				values ($1, $2, $3, $4)
				on conflict do nothing
			`, repo, tag, digest, createdAt)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("insert tag %s:%s: %w", repo, tag, err)
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		total += len(rows)
		slog.Info("tags", "count", total)
		if len(rows) < pageSize {
			break
		}
	}
	slog.Info("tags done", "total", total)
	return nil
}

func migrateBlobs(ctx context.Context, d1 *d1Client, db *sql.DB) error {
	slog.Info("migrating blobs")
	total := 0
	for offset := 0; ; offset += pageSize {
		rows, err := d1.query(ctx, fmt.Sprintf(`
			select repository, digest, size, created_at
			from blobs
			order by repository, digest
			limit %d offset %d
		`, pageSize, offset))
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			break
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, row := range rows {
			repo := str(row["repository"])
			digest := str(row["digest"])
			size := int64(num(row["size"]))
			createdAt := parseTime(row["created_at"])
			_, err := tx.ExecContext(ctx, `
				insert into blobs (repository, digest, size, created_at)
				values ($1, $2, $3, $4)
				on conflict do nothing
			`, repo, digest, size, createdAt)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("insert blob %s@%s: %w", repo, digest, err)
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		total += len(rows)
		slog.Info("blobs", "count", total)
		if len(rows) < pageSize {
			break
		}
	}
	slog.Info("blobs done", "total", total)
	return nil
}

// d1Client queries Cloudflare D1 via REST API.
type d1Client struct {
	accountID  string
	databaseID string
	token      string
	http       *http.Client
}

type d1Response struct {
	Result []struct {
		Results []map[string]any `json:"results"`
		Success bool             `json:"success"`
	} `json:"result"`
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (c *d1Client) query(ctx context.Context, sqlQuery string) ([]map[string]any, error) {
	endpoint := fmt.Sprintf(
		"https://api.cloudflare.com/client/v4/accounts/%s/d1/database/%s/query",
		c.accountID, c.databaseID,
	)

	body, _ := json.Marshal(map[string]any{"sql": sqlQuery, "params": []any{}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("D1 API %d: %s", resp.StatusCode, raw)
	}

	var d1resp d1Response
	if err := json.Unmarshal(raw, &d1resp); err != nil {
		return nil, err
	}
	if !d1resp.Success {
		if len(d1resp.Errors) > 0 {
			return nil, fmt.Errorf("D1 error: %s", d1resp.Errors[0].Message)
		}
		return nil, fmt.Errorf("D1 query failed")
	}
	if len(d1resp.Result) == 0 {
		return nil, nil
	}
	return d1resp.Result[0].Results, nil
}

// helpers

var timeFormats = []string{
	"2006-01-02 15:04:05",
	time.RFC3339,
	"2006-01-02T15:04:05Z",
}

func parseTime(v any) time.Time {
	if v == nil {
		return time.Now().UTC()
	}
	switch t := v.(type) {
	case float64:
		return time.Unix(int64(t), 0).UTC()
	case string:
		for _, format := range timeFormats {
			if parsed, err := time.Parse(format, t); err == nil {
				return parsed.UTC()
			}
		}
		slog.Warn("unparseable timestamp", "value", t)
		return time.Now().UTC()
	}
	return time.Now().UTC()
}

func str(v any) string {
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func num(v any) float64 {
	if v == nil {
		return 0
	}
	f, _ := v.(float64)
	return f
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("missing required env var", "key", key)
		os.Exit(1)
	}
	return v
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
