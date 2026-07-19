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
//
// Blobs in a repository that still has unindexed manifests (size is null) are
// skipped: indexing may still be writing their manifest_blobs rows, and
// deleting would break a live (or soon-to-be-indexed) image. A permanently
// size-null manifest (lost GCS body, unparseable) blocks that repo forever by
// design — prefer a stuck leak over reclaiming live layers; skipped repos are
// logged so the stuck state is visible.
//
// Ordering: the DB row is deleted first (with an unreferenced re-check), then
// the GCS object. The reverse order could leave a live digest with no object.
// There remains a narrow race where a re-upload of the same digest between the
// two steps can lose the fresh object while the new row remains; that class
// predates this change and is not closed here.
func (a *App) runBlobGC(ctx context.Context) error {
	slog.Info("blob gc: start")

	// Surface repos that will be entirely skipped by the unindexed guard so a
	// permanently stuck size-null manifest is not silent storage growth.
	type skipRepo struct {
		repository string
		nullCount  int64
	}
	var skipped []skipRepo
	err := pgctx.Iter(ctx, func(scan pgsql.Scanner) error {
		var s skipRepo
		if err := scan(&s.repository, &s.nullCount); err != nil {
			return err
		}
		skipped = append(skipped, s)
		return nil
	}, `
		select m.repository, count(*)
		from manifests m
		where m.size is null
		group by m.repository
		order by m.repository
	`)
	if err != nil {
		return fmt.Errorf("blob gc: query unindexed repos: %w", err)
	}
	for _, s := range skipped {
		slog.Warn("blob gc: skipping repository with unindexed manifests",
			"repository", s.repository, "size_null_count", s.nullCount)
	}

	type blobRef struct {
		repository string
		digest     string
	}

	var unreferenced []blobRef
	err = pgctx.Iter(ctx, func(scan pgsql.Scanner) error {
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
		  and not exists (
		      select 1 from manifests m
		      where m.repository = b.repository
		        and m.size is null
		  )
	`)
	if err != nil {
		return fmt.Errorf("blob gc: query unreferenced blobs: %w", err)
	}

	if len(unreferenced) == 0 {
		slog.Info("blob gc: no unreferenced blobs found", "skipped_repos", len(skipped))
		return nil
	}

	slog.Info("blob gc: found unreferenced blobs", "count", len(unreferenced), "skipped_repos", len(skipped))
	deleted := 0
	for _, ref := range unreferenced {
		// Delete the DB row first, re-checking that it is still unreferenced so a
		// concurrent index/push cannot lose a now-live blob. Only then remove
		// the GCS object (orphaned objects are cheaper than a live digest with
		// no object).
		res, err := pgctx.Exec(ctx, `
			delete from blobs b
			where b.repository = $1 and b.digest = $2
			  and not exists (
			      select 1 from manifest_blobs mb
			      where mb.repository = b.repository
			        and mb.blob_digest = b.digest
			  )
		`, ref.repository, ref.digest)
		if err != nil {
			slog.Warn("blob gc: delete db record", "repository", ref.repository, "digest", ref.digest, "error", err)
			continue
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			continue
		}
		obj := a.Bucket.Object(fmt.Sprintf("%s/blobs/%s", ref.repository, ref.digest))
		if err := obj.Delete(ctx); err != nil && !isNotFound(err) {
			slog.Warn("blob gc: delete gcs object", "repository", ref.repository, "digest", ref.digest, "error", err)
			// DB row is already gone; leave the object for a later sweep or
			// accept orphan storage rather than resurrecting an unreferenced row.
		}
		deleted++
	}
	slog.Info("blob gc: complete", "deleted", deleted, "total", len(unreferenced), "skipped_repos", len(skipped))
	return nil
}
