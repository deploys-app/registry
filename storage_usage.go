package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/acoshift/pgsql"
	"github.com/acoshift/pgsql/pgctx"
)

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

	for _, u := range usages {
		if _, err := pgctx.Exec(ctx, `
			insert into project_storage_usage (namespace, size, updated_at)
			values ($1, $2, now())
			on conflict (namespace) do update set size = $2, updated_at = now()
		`, u.namespace, u.size); err != nil {
			return fmt.Errorf("calculate project storage: upsert %s: %w", u.namespace, err)
		}
	}

	slog.Info("calculate project storage: complete", "projects", len(usages))
	return nil
}
