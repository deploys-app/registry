package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/acoshift/pgsql"
	"github.com/acoshift/pgsql/pgctx"
)

// runBlobGC deletes blobs that are not referenced by any manifest and are
// older than 1 day (grace period for in-flight manifest pushes that have
// uploaded blobs but not yet pushed the manifest).
func (a *App) runBlobGC(ctx context.Context) error {
	slog.Info("blob gc: start")

	type blobRef struct {
		repository string
		digest     string
	}

	var unreferenced []blobRef
	err := pgctx.Iter(ctx, func(scan pgsql.Scanner) error {
		var ref blobRef
		if err := scan(&ref.repository, &ref.digest); err != nil {
			return err
		}
		unreferenced = append(unreferenced, ref)
		return nil
	}, `
		select b.repository, b.digest
		from blobs b
		where b.created_at < now() - interval '1 day'
		  and not exists (
		      select 1 from manifest_blobs mb
		      where mb.repository = b.repository
		        and mb.blob_digest = b.digest
		  )
	`)
	if err != nil {
		return fmt.Errorf("blob gc: query unreferenced blobs: %w", err)
	}

	if len(unreferenced) == 0 {
		slog.Info("blob gc: no unreferenced blobs found")
		return nil
	}

	slog.Info("blob gc: found unreferenced blobs", "count", len(unreferenced))
	deleted := 0
	for _, ref := range unreferenced {
		obj := a.Bucket.Object(fmt.Sprintf("%s/blobs/%s", ref.repository, ref.digest))
		if err := obj.Delete(ctx); err != nil && !isNotFound(err) {
			slog.Warn("blob gc: delete gcs object", "repository", ref.repository, "digest", ref.digest, "error", err)
			continue
		}
		if _, err := pgctx.Exec(ctx, `
			delete from blobs where repository = $1 and digest = $2
		`, ref.repository, ref.digest); err != nil {
			slog.Warn("blob gc: delete db record", "repository", ref.repository, "digest", ref.digest, "error", err)
			continue
		}
		deleted++
	}
	slog.Info("blob gc: complete", "deleted", deleted, "total", len(unreferenced))
	return nil
}
