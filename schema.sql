create table repositories (
	name       text    not null,
	created_at integer not null default current_timestamp,
	primary key (name)
);

create table manifests (
	repository text    not null,
	digest     text    not null,
	created_at integer not null default current_timestamp,
	updated_at integer not null default current_timestamp,
	primary key (repository, digest),
	foreign key (repository) references repositories (name)
);

create table tags (
	repository text    not null,
	tag        text    not null,
	digest     text    not null,
	created_at integer not null default current_timestamp,
	primary key (repository, tag),
	foreign key (repository) references repositories (name),
	foreign key (repository, digest) references manifests (repository, digest)
);

create table blobs (
	repository text    not null,
	digest     text    not null,
	size       integer not null,
	created_at integer not null default current_timestamp,
	primary key (repository, digest),
	foreign key (repository) references repositories (name)
);
