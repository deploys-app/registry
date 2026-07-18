create table repositories (
	name       text        not null primary key,
	namespace  text        not null,
	created_at timestamptz not null default now()
);
create index repositories_namespace_idx on repositories (namespace);

create table manifests (
	repository text        not null,
	digest     text        not null,
	size       bigint,
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now(),
	primary key (repository, digest),
	foreign key (repository) references repositories (name)
);

create table tags (
	repository text        not null,
	tag        text        not null,
	digest     text        not null,
	created_at timestamptz not null default now(),
	primary key (repository, tag),
	foreign key (repository) references repositories (name),
	foreign key (repository, digest) references manifests (repository, digest)
);

create table blobs (
	repository text        not null,
	digest     text        not null,
	size       bigint      not null,
	created_at timestamptz not null default now(),
	primary key (repository, digest)
);

create table manifest_blobs (
	repository      text not null,
	manifest_digest text not null,
	blob_digest     text not null,
	primary key (repository, manifest_digest, blob_digest),
	foreign key (repository, manifest_digest) references manifests (repository, digest)
);
create index manifest_blobs_blob_idx on manifest_blobs (repository, blob_digest);

-- Image index / manifest list → child manifest digests. Used by registry.gc so
-- a kept multi-arch index also retains its platform manifests (and thus their
-- layer blobs via manifest_blobs).
create table manifest_children (
	repository    text not null,
	parent_digest text not null,
	child_digest  text not null,
	primary key (repository, parent_digest, child_digest),
	foreign key (repository, parent_digest) references manifests (repository, digest)
);
create index manifest_children_child_idx on manifest_children (repository, child_digest);

create table project_storage_usage (
	namespace  text        not null primary key,
	size       bigint      not null default 0,
	updated_at timestamptz not null default now()
);
