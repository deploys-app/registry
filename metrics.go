package main

import (
	"github.com/moonrhythm/parapet/pkg/prom"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	egressBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "deploys_registry_egress_bytes",
		Help: "Total bytes served from registry per project.",
	}, []string{"project_id"})

	downloadCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "deploys_registry_download_count",
		Help: "Total blob download requests per project.",
	}, []string{"project_id"})

	uploadBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "deploys_registry_upload_bytes",
		Help: "Total uploaded blob bytes per project.",
	}, []string{"project_id"})

	uploadCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "deploys_registry_upload_count",
		Help: "Total blob upload requests per project.",
	}, []string{"project_id"})
)

func init() {
	prom.Registry().MustRegister(
		egressBytes,
		downloadCount,
		uploadBytes,
		uploadCount,
	)
}
