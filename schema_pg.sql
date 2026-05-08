create table repositories (
	name       text        not null primary key,
	namespace  text        not null,
	created_at timestamptz not null default now()
);
create index repositories_namespace_idx on repositories (namespace);

create table manifests (
	repository text        not null,
	digest     text        not null,
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
