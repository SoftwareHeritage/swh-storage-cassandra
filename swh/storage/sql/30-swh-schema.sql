---
--- SQL implementation of the Software Heritage data model
---

-- schema versions
create table dbversion
(
  version     int primary key,
  release     timestamptz,
  description text
);

comment on table dbversion is 'Details of current db version';
comment on column dbversion.version is 'SQL schema version';
comment on column dbversion.release is 'Version deployment timestamp';
comment on column dbversion.description is 'Release description';

-- latest schema version
insert into dbversion(version, release, description)
      values(138, now(), 'Work In Progress');

-- a SHA1 checksum
create domain sha1 as bytea check (length(value) = 20);

-- a Git object ID, i.e., a Git-style salted SHA1 checksum
create domain sha1_git as bytea check (length(value) = 20);

-- a SHA256 checksum
create domain sha256 as bytea check (length(value) = 32);

-- a blake2 checksum
create domain blake2s256 as bytea check (length(value) = 32);

-- UNIX path (absolute, relative, individual path component, etc.)
create domain unix_path as bytea;

-- a set of UNIX-like access permissions, as manipulated by, e.g., chmod
create domain file_perms as int;


-- Checksums about actual file content. Note that the content itself is not
-- stored in the DB, but on external (key-value) storage. A single checksum is
-- used as key there, but the other can be used to verify that we do not inject
-- content collisions not knowingly.
create table content
(
  sha1       sha1 not null,
  sha1_git   sha1_git not null,
  sha256     sha256 not null,
  blake2s256 blake2s256,
  length     bigint not null,
  ctime      timestamptz not null default now(),
             -- creation time, i.e. time of (first) injection into the storage
  status     content_status not null default 'visible',
  object_id  bigserial
);

comment on table content is 'Checksums of file content which is actually stored externally';
comment on column content.sha1 is 'Content sha1 hash';
comment on column content.sha1_git is 'Git object sha1 hash';
comment on column content.sha256 is 'Content Sha256 hash';
comment on column content.blake2s256 is 'Content blake2s hash';
comment on column content.length is 'Content length';
comment on column content.ctime is 'First seen time';
comment on column content.status is 'Content status (absent, visible, hidden)';
comment on column content.object_id is 'Content identifier';


-- An origin is a place, identified by an URL, where software source code
-- artifacts can be found. We support different kinds of origins, e.g., git and
-- other VCS repositories, web pages that list tarballs URLs (e.g.,
-- http://www.kernel.org), indirect tarball URLs (e.g.,
-- http://www.example.org/latest.tar.gz), etc. The key feature of an origin is
-- that it can be *fetched* from (wget, git clone, svn checkout, etc.) to
-- retrieve all the contained software.
create table origin
(
  id       bigserial not null,
  type     text, -- TODO use an enum here (?)
  url      text not null
);

comment on column origin.id is 'Artifact origin id';
comment on column origin.type is 'Type of origin';
comment on column origin.url is 'URL of origin';


-- Content blobs observed somewhere, but not ingested into the archive for
-- whatever reason. This table is separate from the content table as we might
-- not have the sha1 checksum of skipped contents (for instance when we inject
-- git repositories, objects that are too big will be skipped here, and we will
-- only know their sha1_git). 'reason' contains the reason the content was
-- skipped. origin is a nullable column allowing to find out which origin
-- contains that skipped content.
create table skipped_content
(
  sha1       sha1,
  sha1_git   sha1_git,
  sha256     sha256,
  blake2s256 blake2s256,
  length     bigint not null,
  ctime      timestamptz not null default now(),
  status     content_status not null default 'absent',
  reason     text not null,
  origin     bigint,
  object_id  bigserial
);

comment on table skipped_content is 'Content blobs observed, but not ingested in the archive';
comment on column skipped_content.sha1 is 'Skipped content sha1 hash';
comment on column skipped_content.sha1_git is 'Git object sha1 hash';
comment on column skipped_content.sha256 is 'Skipped content sha256 hash';
comment on column skipped_content.blake2s256 is 'Skipped content blake2s hash';
comment on column skipped_content.length is 'Skipped content length';
comment on column skipped_content.ctime is 'First seen time';
comment on column skipped_content.status is 'Skipped content status (absent, visible, hidden)';
comment on column skipped_content.reason is 'Reason for skipping';
comment on column skipped_content.origin is 'Origin table identifier';
comment on column skipped_content.object_id is 'Skipped content identifier';


-- Log of all origin fetches (i.e., origin crawling) that have been done in the
-- past, or are still ongoing. Similar to list_history, but for origins.
create table fetch_history
(
  id        bigserial,
  origin    bigint,
  date      timestamptz not null,
  status    boolean,  -- true if and only if the fetch has been successful
  result    jsonb,     -- more detailed returned values, times, etc...
  stdout    text,
  stderr    text,     -- null when status is true, filled otherwise
  duration  interval  -- fetch duration of NULL if still ongoing
);

comment on table fetch_history is 'Log of all origin fetches';
comment on column fetch_history.id is 'Identifier for fetch history';
comment on column fetch_history.origin is 'Origin table identifier';
comment on column fetch_history.date is 'Fetch start time';
comment on column fetch_history.status is 'True indicates successful fetch';
comment on column fetch_history.result is 'Detailed return values, times etc';
comment on column fetch_history.stdout is 'Standard output of fetch operation';
comment on column fetch_history.stderr is 'Standard error of fetch operation';
comment on column fetch_history.duration is 'Time taken to complete fetch, NULL if ongoing';


-- A file-system directory.  A directory is a list of directory entries (see
-- tables: directory_entry_{dir,file}).
--
-- To list the contents of a directory:
-- 1. list the contained directory_entry_dir using array dir_entries
-- 2. list the contained directory_entry_file using array file_entries
-- 3. list the contained directory_entry_rev using array rev_entries
-- 4. UNION
--
-- Synonyms/mappings:
-- * git: tree
create table directory
(
  id            sha1_git not null,
  dir_entries   bigint[],  -- sub-directories, reference directory_entry_dir
  file_entries  bigint[],  -- contained files, reference directory_entry_file
  rev_entries   bigint[],  -- mounted revisions, reference directory_entry_rev
  object_id     bigserial  -- short object identifier
);

comment on table directory is 'Contents of a directory, synonymous to tree (git)';
comment on column directory.id is 'Git object sha1 hash';
comment on column directory.dir_entries is 'Sub-directories, reference directory_entry_dir';
comment on column directory.file_entries is 'Contained files, reference directory_entry_file';
comment on column directory.rev_entries is 'Mounted revisions, reference directory_entry_rev';
comment on column directory.object_id is 'Short object identifier';


-- A directory entry pointing to a (sub-)directory.
create table directory_entry_dir
(
  id      bigserial,
  target  sha1_git,   -- id of target directory
  name    unix_path,  -- path name, relative to containing dir
  perms   file_perms  -- unix-like permissions
);

comment on table directory_entry_dir is 'Directory entry for directory';
comment on column directory_entry_dir.id is 'Directory identifier';
comment on column directory_entry_dir.target is 'Target directory identifier';
comment on column directory_entry_dir.name is 'Path name, relative to containing directory';
comment on column directory_entry_dir.perms is 'Unix-like permissions';


-- A directory entry pointing to a file content.
create table directory_entry_file
(
  id      bigserial,
  target  sha1_git,   -- id of target file
  name    unix_path,  -- path name, relative to containing dir
  perms   file_perms  -- unix-like permissions
);

comment on table directory_entry_file is 'Directory entry for file';
comment on column directory_entry_file.id is 'File identifier';
comment on column directory_entry_file.target is 'Target file identifier';
comment on column directory_entry_file.name is 'Path name, relative to containing directory';
comment on column directory_entry_file.perms is 'Unix-like permissions';


-- A directory entry pointing to a revision.
create table directory_entry_rev
(
  id      bigserial,
  target  sha1_git,   -- id of target revision
  name    unix_path,  -- path name, relative to containing dir
  perms   file_perms  -- unix-like permissions
);

comment on table directory_entry_rev is 'Directory entry for revision';
comment on column directory_entry_dir.id is 'Revision identifier';
comment on column directory_entry_dir.target is 'Target revision in identifier';
comment on column directory_entry_dir.name is 'Path name, relative to containing directory';
comment on column directory_entry_dir.perms is 'Unix-like permissions';


-- A person referenced by some source code artifacts, e.g., a VCS revision or
-- release metadata.
create table person
(
  id        bigserial,
  name      bytea,          -- advisory: not null if we managed to parse a name
  email     bytea,          -- advisory: not null if we managed to parse an email
  fullname  bytea not null  -- freeform specification; what is actually used in the checksums
                            --     will usually be of the form 'name <email>'
);

comment on table person is 'Person referenced in code artifact release metadata';
comment on column person.id is 'Person identifier';
comment on column person.name is 'Name';
comment on column person.email is 'Email';
comment on column person.fullname is 'Full name (raw name)';


-- The state of a source code tree at a specific point in time.
--
-- Synonyms/mappings:
-- * git / subversion / etc: commit
-- * tarball: a specific tarball
--
-- Revisions are organized as DAGs. Each revision points to 0, 1, or more (in
-- case of merges) parent revisions. Each revision points to a directory, i.e.,
-- a file-system tree containing files and directories.
create table revision
(
  id                    sha1_git not null,
  date                  timestamptz,
  date_offset           smallint,
  committer_date        timestamptz,
  committer_date_offset smallint,
  type                  revision_type not null,
  directory             sha1_git,  -- source code 'root' directory
  message               bytea,
  author                bigint,
  committer             bigint,
  synthetic             boolean not null default false,  -- true iff revision has been created by Software Heritage
  metadata              jsonb,  -- extra metadata (tarball checksums, extra commit information, etc...)
  object_id             bigserial,
  date_neg_utc_offset   boolean,
  committer_date_neg_utc_offset boolean
);

comment on table revision is 'Revision represents the state of a source code tree at a 
 specific point in time';
comment on column revision.id is 'Git id of sha1 checksum';
comment on column revision.date is 'Timestamp when revision was authored';
comment on column revision.date_offset is 'Authored timestamp offset from UTC';
comment on column revision.committer_date is 'Timestamp when revision was committed';
comment on column revision.committer_date_offset is 'Committed timestamp offset from UTC';
comment on column revision.type is 'Possible revision types (''git'', ''tar'', ''dsc'', ''svn'', ''hg'')';
comment on column revision.directory is 'Directory identifier';
comment on column revision.message is 'Revision message';
comment on column revision.author is 'Author identifier';
comment on column revision.committer is 'Committer identifier';
comment on column revision.synthetic is 'true iff revision has been created by Software Heritage';
comment on column revision.metadata is 'extra metadata (tarball checksums, extra commit information, etc...)';
comment on column revision.object_id is 'Object identifier';
comment on column revision.date_neg_utc_offset is 'True indicates -0 UTC offset for author timestamp';
comment on column revision.committer_date_neg_utc_offset is 'True indicates -0 UTC offset for committer timestamp';


-- either this table or the sha1_git[] column on the revision table
create table revision_history
(
  id           sha1_git not null,
  parent_id    sha1_git not null,
  parent_rank  int not null default 0
    -- parent position in merge commits, 0-based
);

comment on table revision_history is 'Sequence of revision history with parent and position in history';
comment on column revision_history.id is 'Revision history git object sha1 checksum';
comment on column revision_history.parent_id is 'Parent revision git object identifier';
comment on column revision_history.parent_rank is 'Parent position in merge commits, 0-based';


-- Crawling history of software origins visited by Software Heritage. Each
-- visit is a 3-way mapping between a software origin, a timestamp, and a
-- snapshot object capturing the full-state of the origin at visit time.
create table origin_visit
(
  origin       bigint not null,
  visit        bigint not null,
  date         timestamptz not null,
  type         text not null,
  status       origin_visit_status not null,
  metadata     jsonb,
  snapshot     sha1_git
);

comment on column origin_visit.origin is 'Visited origin';
comment on column origin_visit.visit is 'Sequential visit number for the origin';
comment on column origin_visit.date is 'Visit timestamp';
comment on column origin_visit.type is 'Type of loader that did the visit (hg, git, ...)';
comment on column origin_visit.status is 'Visit result';
comment on column origin_visit.metadata is 'Origin metadata at visit time';
comment on column origin_visit.snapshot is 'Origin snapshot at visit time';


-- A snapshot represents the entire state of a software origin as crawled by
-- Software Heritage. This table is a simple mapping between (public) intrinsic
-- snapshot identifiers and (private) numeric sequential identifiers.
create table snapshot
(
  object_id  bigserial not null,  -- PK internal object identifier
  id         sha1_git not null    -- snapshot intrinsic identifier
);

comment on table snapshot is 'State of a software origin as crawled by Software Heritage';
comment on column snapshot.object_id is 'Internal object identifier';
comment on column snapshot.id is 'Intrinsic snapshot identifier';


-- Each snapshot associate "branch" names to other objects in the Software
-- Heritage Merkle DAG. This table describes branches as mappings between names
-- and target typed objects.
create table snapshot_branch
(
  object_id    bigserial not null,  -- PK internal object identifier
  name         bytea not null,      -- branch name, e.g., "master" or "feature/drag-n-drop"
  target       bytea,               -- target object identifier, e.g., a revision identifier
  target_type  snapshot_target      -- target object type, e.g., "revision"
);

comment on table snapshot_branch is 'Associates branches with objects in Heritage Merkle DAG';
comment on column snapshot_branch.object_id is 'Internal object identifier';
comment on column snapshot_branch.name is 'Branch name';
comment on column snapshot_branch.target is 'Target object identifier';
comment on column snapshot_branch.target_type is 'Target object type';


-- Mapping between snapshots and their branches.
create table snapshot_branches
(
  snapshot_id  bigint not null,  -- snapshot identifier, ref. snapshot.object_id
  branch_id    bigint not null   -- branch identifier, ref. snapshot_branch.object_id
);

comment on table snapshot_branches is 'Mapping between snapshot and their branches';
comment on column snapshot_branches.snapshot_id is 'Snapshot identifier';
comment on column snapshot_branches.branch_id is 'Branch identifier';


-- A "memorable" point in time in the development history of a software
-- project.
--
-- Synonyms/mappings:
-- * git: tag (of the annotated kind, otherwise they are just references)
-- * tarball: the release version number
create table release
(
  id          sha1_git not null,
  target      sha1_git,
  date        timestamptz,
  date_offset smallint,
  name        bytea,
  comment     bytea,
  author      bigint,
  synthetic   boolean not null default false,  -- true iff release has been created by Software Heritage
  object_id   bigserial,
  target_type object_type not null,
  date_neg_utc_offset  boolean
);

comment on table release is 'Details of a software release, synonymous with
 a tag (git) or version number (tarball)';
comment on column release.id is 'Release git identifier';
comment on column release.target is 'Target git identifier';
comment on column release.date is 'Release timestamp';
comment on column release.date_offset is 'Timestamp offset from UTC';
comment on column release.name is 'Name';
comment on column release.comment is 'Comment';
comment on column release.author is 'Author';
comment on column release.synthetic is 'Indicates if created by Software Heritage';
comment on column release.object_id is 'Object identifier';
comment on column release.target_type is 'Object type (''content'', ''directory'', ''revision'',
 ''release'', ''snapshot'')';
comment on column release.date_neg_utc_offset is 'True indicates -0 UTC offset for release timestamp';

-- Tools
create table tool
(
  id serial not null,
  name text not null,
  version text not null,
  configuration jsonb
);

comment on table tool is 'Tool information';
comment on column tool.id is 'Tool identifier';
comment on column tool.version is 'Tool name';
comment on column tool.version is 'Tool version';
comment on column tool.configuration is 'Tool configuration: command line, flags, etc...';


create table metadata_provider
(
  id            serial not null,
  provider_name text   not null,
  provider_type text   not null,
  provider_url  text,
  metadata      jsonb
);

comment on table metadata_provider is 'Metadata provider information';
comment on column metadata_provider.id is 'Provider''s identifier';
comment on column metadata_provider.provider_name is 'Provider''s name';
comment on column metadata_provider.provider_url is 'Provider''s url';
comment on column metadata_provider.metadata is 'Other metadata about provider';


-- Discovery of metadata during a listing, loading, deposit or external_catalog of an origin
-- also provides a translation to a defined json schema using a translation tool (tool_id)
create table origin_metadata
(
  id             bigserial     not null,  -- PK internal object identifier
  origin_id      bigint        not null,  -- references origin(id)
  discovery_date timestamptz   not null,  -- when it was extracted
  provider_id    bigint        not null,  -- ex: 'hal', 'lister-github', 'loader-github'
  tool_id        bigint        not null,
  metadata       jsonb         not null
);

comment on table origin_metadata is 'keeps all metadata found concerning an origin';
comment on column origin_metadata.id is 'the origin_metadata object''s id';
comment on column origin_metadata.origin_id is 'the origin id for which the metadata was found';
comment on column origin_metadata.discovery_date is 'the date of retrieval';
comment on column origin_metadata.provider_id is 'the metadata provider: github, openhub, deposit, etc.';
comment on column origin_metadata.tool_id is 'the tool used for extracting metadata: lister-github, etc.';
comment on column origin_metadata.metadata is 'metadata in json format but with original terms';


-- Keep a cache of object counts
create table object_counts
(
  object_type text,             -- table for which we're counting objects (PK)
  value bigint,                 -- count of objects in the table
  last_update timestamptz,      -- last update for the object count in this table
  single_update boolean         -- whether we update this table standalone (true) or through bucketed counts (false)
);

comment on table object_counts is 'Cache of object counts';
comment on column object_counts.object_type is 'Object type (''content'', ''directory'', ''revision'',
 ''release'', ''snapshot'')';
comment on column object_counts.value is 'Count of objects in the table';
comment on column object_counts.last_update is 'Last update for object count';
comment on column object_counts.single_update is 'standalone (true) or bucketed counts (false)';


create table object_counts_bucketed
(
    line serial not null,       -- PK
    object_type text not null,  -- table for which we're counting objects
    identifier text not null,   -- identifier across which we're bucketing objects
    bucket_start bytea,         -- lower bound (inclusive) for the bucket
    bucket_end bytea,           -- upper bound (exclusive) for the bucket
    value bigint,               -- count of objects in the bucket
    last_update timestamptz     -- last update for the object count in this bucket
);

comment on table object_counts_bucketed is 'Bucketed count for objects ordered by type';
comment on column object_counts_bucketed.line is 'Auto incremented idenitfier value';
comment on column object_counts_bucketed.object_type is 'Object type (''content'', ''directory'', ''revision'',
 ''release'', ''snapshot'')';
comment on column object_counts_bucketed.identifier is 'Common identifier for bucketed objects';
comment on column object_counts_bucketed.bucket_start is 'Lower bound (inclusive) for the bucket';
comment on column object_counts_bucketed.bucket_end is 'Upper bound (exclusive) for the bucket';
comment on column object_counts_bucketed.value is 'Count of objects in the bucket';
comment on column object_counts_bucketed.last_update is 'Last update for the object count in this bucket';

