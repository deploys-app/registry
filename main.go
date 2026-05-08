package main

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"time"

	"cloud.google.com/go/storage"
	"github.com/acoshift/configfile"
	"github.com/acoshift/pgsql/pgctx"
	_ "github.com/lib/pq"
	"github.com/moonrhythm/parapet"
	"github.com/moonrhythm/parapet/pkg/healthz"
	"github.com/moonrhythm/parapet/pkg/logger"
)

var config = configfile.NewEnvReader()

func main() {
	ctx := context.Background()

	db, err := sql.Open("postgres", config.MustString("db_url"))
	if err != nil {
		slog.Error("open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	db.SetMaxIdleConns(10)
	db.SetMaxOpenConns(10)
	db.SetConnMaxLifetime(10 * time.Minute)

	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		slog.Error("create storage client", "error", err)
		os.Exit(1)
	}
	defer storageClient.Close()

	bucket := storageClient.Bucket(config.MustString("bucket_name"))

	app := &App{Bucket: bucket, DB: db}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("Deploys.app Registry Service"))
	})
	mux.Handle("/v2/", authMiddleware(http.HandlerFunc(app.registryHandler)))
	mux.Handle("/api/", http.HandlerFunc(app.apiHandler))

	port := config.StringDefault("PORT", "8080")
	slog.Info("start registry", "addr", ":"+port)

	srv := parapet.NewBackend()
	srv.Addr = ":" + port
	srv.Use(healthz.New())
	srv.Use(logger.Stdout())
	srv.UseFunc(pgctx.Middleware(db))
	srv.Handler = mux

	if err := srv.ListenAndServe(); err != nil {
		slog.Error("listen and serve", "error", err)
		os.Exit(1)
	}
}
