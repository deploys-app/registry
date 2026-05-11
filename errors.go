package main

import "github.com/acoshift/arpc/v2"

var (
	errForbidden        = arpc.NewError("iam: forbidden")
	errRepoNotFound     = arpc.NewError("repository not found")
	errManifestNotFound = arpc.NewError("manifest not found")
	errTagNotFound      = arpc.NewError("tag not found")
)
