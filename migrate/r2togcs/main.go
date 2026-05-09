// r2togcs migrates objects from Cloudflare R2 to Google Cloud Storage.
//
// Required env vars:
//
//	R2_ACCOUNT_ID        - Cloudflare account ID
//	R2_ACCESS_KEY_ID     - R2 access key ID
//	R2_SECRET_ACCESS_KEY - R2 secret access key
//	BUCKET_NAME          - GCS destination bucket name
//
// Optional env vars:
//
//	R2_BUCKET - R2 source bucket name (default: deploys-registry)
//	WORKERS   - number of parallel copy workers (default: 8)
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"golang.org/x/sync/errgroup"
)

const defaultR2Bucket = "deploys-registry"

func main() {
	accountID := mustEnv("R2_ACCOUNT_ID")
	accessKeyID := mustEnv("R2_ACCESS_KEY_ID")
	secretKey := mustEnv("R2_SECRET_ACCESS_KEY")
	gcsBucketName := mustEnv("BUCKET_NAME")
	r2Bucket := envDefault("R2_BUCKET", defaultR2Bucket)
	workers := envInt("WORKERS", 8)

	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKeyID, secretKey, "")),
		config.WithRegion("auto"),
	)
	if err != nil {
		slog.Error("create R2 config", "error", err)
		os.Exit(1)
	}
	r2 := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID))
		o.UsePathStyle = true
	})

	gcsClient, err := storage.NewClient(ctx)
	if err != nil {
		slog.Error("create GCS client", "error", err)
		os.Exit(1)
	}
	defer gcsClient.Close()
	gcsBucket := gcsClient.Bucket(gcsBucketName)

	keys := make(chan string)

	g, ctx := errgroup.WithContext(ctx)

	// producer: list all R2 objects
	g.Go(func() error {
		defer close(keys)
		paginator := s3.NewListObjectsV2Paginator(r2, &s3.ListObjectsV2Input{
			Bucket: aws.String(r2Bucket),
		})
		total := 0
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return fmt.Errorf("list R2 objects: %w", err)
			}
			for _, obj := range page.Contents {
				key := aws.ToString(obj.Key)
				if strings.HasPrefix(key, "_uploads/") {
					continue
				}
				select {
				case keys <- key:
					total++
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
		slog.Info("listed R2 objects", "total", total)
		return nil
	})

	// consumers: copy each object to GCS
	for range workers {
		g.Go(func() error {
			for key := range keys {
				if err := copyObject(ctx, r2, r2Bucket, gcsBucket, key); err != nil {
					slog.Error("copy object", "key", key, "error", err)
					// log and continue rather than aborting all workers
				}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		slog.Error("migration failed", "error", err)
		os.Exit(1)
	}
	slog.Info("migration complete")
}

func copyObject(ctx context.Context, r2 *s3.Client, r2Bucket string, gcsBucket *storage.BucketHandle, key string) error {
	gcsObj := gcsBucket.Object(key)

	// skip if already exists in GCS
	if _, err := gcsObj.Attrs(ctx); err == nil {
		slog.Debug("skip (already exists)", "key", key)
		return nil
	}

	out, err := r2.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(r2Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("get from R2: %w", err)
	}
	defer out.Body.Close()

	contentType := aws.ToString(out.ContentType)
	digest := digestFromKey(key)

	wc := gcsObj.NewWriter(ctx)
	wc.ContentType = contentType

	if digest != "" {
		// digest known from key — stream directly
		wc.ObjectAttrs.Metadata = map[string]string{"docker-content-digest": digest}
		if _, err := io.Copy(wc, out.Body); err != nil {
			wc.Close()
			return fmt.Errorf("write to GCS: %w", err)
		}
	} else {
		// tag-addressed manifest — buffer to compute SHA256
		body, err := io.ReadAll(out.Body)
		if err != nil {
			wc.Close()
			return fmt.Errorf("read from R2: %w", err)
		}
		sum := sha256.Sum256(body)
		digest = fmt.Sprintf("sha256:%x", sum)
		wc.ObjectAttrs.Metadata = map[string]string{"docker-content-digest": digest}
		if _, err := io.Copy(wc, bytes.NewReader(body)); err != nil {
			wc.Close()
			return fmt.Errorf("write to GCS: %w", err)
		}
	}

	if err := wc.Close(); err != nil {
		return fmt.Errorf("close GCS writer: %w", err)
	}

	slog.Info("copied", "key", key, "digest", digest)
	return nil
}

// digestFromKey returns the digest if it is encoded in the object key, or empty
// string for tag-addressed manifests where the digest must be computed.
func digestFromKey(key string) string {
	parts := strings.Split(key, "/")
	last := parts[len(parts)-1]
	if strings.HasPrefix(last, "sha256:") {
		return last
	}
	return ""
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

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
