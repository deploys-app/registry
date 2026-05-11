package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/acoshift/pgsql"
	"github.com/acoshift/pgsql/pgctx"
	"github.com/acoshift/pgsql/pgstmt"
)

const storageChunkSize = 1000

// calculateProjectStorage sums blob sizes per project namespace and upserts
// the result into project_storage_usage. Intended to run once per day via
// the /internal/runAll scheduler endpoint.
func (a *App) calculateProjectStorage(ctx context.Context) error {
	slog.Info("calculate project storage: start")

	type projectUsage struct {
		namespace string
		size      int64
	}

	var usages []projectUsage
	err := pgctx.Iter(ctx, func(scan pgsql.Scanner) error {
		var u projectUsage
		if err := scan(&u.namespace, &u.size); err != nil {
			return err
		}
		usages = append(usages, u)
		return nil
	}, `
		select r.namespace, coalesce(sum(b.size), 0)
		from repositories r
		left join blobs b on b.repository = r.name
		group by r.namespace
	`)
	if err != nil {
		return fmt.Errorf("calculate project storage: query: %w", err)
	}

	if len(usages) == 0 {
		slog.Info("calculate project storage: no projects found")
		return nil
	}

	for i := 0; i < len(usages); i += storageChunkSize {
		chunk := usages[i:min(i+storageChunkSize, len(usages))]
		_, err := pgstmt.Insert(func(b pgstmt.InsertStatement) {
			b.Into("project_storage_usage")
			b.Columns("namespace", "size", "updated_at")
			for _, u := range chunk {
				b.Value(u.namespace, u.size, pgstmt.Default)
			}
			b.OnConflictOnConstraint("project_storage_usage_pkey").DoUpdate(func(b pgstmt.UpdateStatement) {
				b.Set("size").ToRaw("excluded.size")
				b.Set("updated_at").ToRaw("now()")
			})
		}).ExecWith(ctx)
		if err != nil {
			return fmt.Errorf("calculate project storage: upsert: %w", err)
		}
	}

	slog.Info("calculate project storage: complete", "projects", len(usages))
	return nil
}
