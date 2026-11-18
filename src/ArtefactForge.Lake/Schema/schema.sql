-- The evidence lake's fixed tables and views. The raw_<kind> tables are not here: each is created
-- from the columns of the first CSV loaded into it, and widened when a later file has more.

CREATE TABLE lake_meta (
    key   VARCHAR PRIMARY KEY,
    value VARCHAR
);

-- One row per host folder. host is the folder name (the collection name), which an analyst can
-- rename; hostname is the machine's own name when the folder's outputs.json records it.
CREATE TABLE hosts (
    host          VARCHAR PRIMARY KEY,
    hostname      VARCHAR,
    platform      VARCHAR,
    time_zone     VARCHAR,
    collected_utc TIMESTAMP,
    collector     VARCHAR,
    producer      VARCHAR,
    manifest      BOOLEAN NOT NULL   -- true when the sources came from outputs.json
);

-- Every file the build looked at, loaded or not, and why. A source that was not loaded is never
-- left out of this table: it is how a gap in the lake is seen.
CREATE TABLE sources (
    source_id      INTEGER PRIMARY KEY,
    host           VARCHAR NOT NULL,
    path           VARCHAR NOT NULL,  -- relative to the host folder, '/' separators
    kind           VARCHAR,           -- e.g. pecmd.timeline, or unmapped.<parser>
    parser         VARCHAR,
    parser_version VARCHAR,           -- 'unknown' when there was no outputs.json
    output_status  VARCHAR,           -- the status outputs.json gave the file, if any
    status         VARCHAR NOT NULL,  -- loaded, skipped, header_mismatch, failed
    reason         VARCHAR,
    raw_table      VARCHAR,
    mapping        VARCHAR,           -- the kind whose map.sql put its rows in timeline
    mapping_version INTEGER,
    rows_loaded    BIGINT,
    rows_rejected  BIGINT,
    timeline_rows  BIGINT,
    size           BIGINT,
    mtime          TIMESTAMP
);

-- The cross-host timeline: one row per timestamped event, from the raw tables by one reviewed
-- mapping per kind. source_id and row_no lead back to the exact row of the exact CSV.
CREATE TABLE timeline (
    ts            TIMESTAMP NOT NULL, -- UTC
    ts_raw        VARCHAR,            -- as the CSV had it (EZ Tools write 100 ns digits)
    ts_desc       VARCHAR,            -- what the time means: created, modified, executed ...
    host          VARCHAR NOT NULL,
    platform      VARCHAR,
    kind          VARCHAR NOT NULL,
    category      VARCHAR NOT NULL,
    action        VARCHAR,
    user_name     VARCHAR,
    user_sid      VARCHAR,
    user_domain   VARCHAR,
    path          VARCHAR,
    file_name     VARCHAR,
    extension     VARCHAR,            -- lower case, with the dot: '.exe'
    size          BIGINT,
    process_path  VARCHAR,
    process_id    BIGINT,
    parent_path   VARCHAR,
    command_line  VARCHAR,
    sha1          VARCHAR,
    sha256        VARCHAR,
    md5           VARCHAR,
    src_ip        VARCHAR,
    src_port      INTEGER,
    dst_ip        VARCHAR,
    dst_port      INTEGER,
    domain        VARCHAR,
    bytes_in      BIGINT,
    bytes_out     BIGINT,
    url           VARCHAR,
    http_method   VARCHAR,
    http_status   INTEGER,
    user_agent    VARCHAR,
    event_id      INTEGER,
    channel       VARCHAR,
    provider      VARCHAR,
    logon_type    VARCHAR,
    rule_title    VARCHAR,
    severity      VARCHAR,
    summary       VARCHAR,
    source_id     INTEGER NOT NULL,
    row_no        BIGINT NOT NULL
);

-- What ran where: one row per host and program, first and last seen across every execution
-- source mapped so far. lower(file_name) is the cross-host key, as paths differ by volume.
CREATE VIEW executions AS
SELECT host,
       lower(file_name)          AS program,
       any_value(path)           AS path,
       any_value(sha1)           AS sha1,
       min(ts)                   AS first_seen,
       max(ts)                   AS last_seen,
       count(*)                  AS events,
       list(DISTINCT kind ORDER BY kind) AS kinds
FROM timeline
WHERE category IN ('execution', 'process') AND file_name IS NOT NULL
GROUP BY host, lower(file_name);

CREATE VIEW logons AS
SELECT ts, ts_raw, host, action, event_id, logon_type, user_domain, user_name, user_sid,
       src_ip, process_path, channel, summary, source_id, row_no
FROM timeline
WHERE category = 'logon';

CREATE VIEW file_events AS
SELECT ts, ts_raw, ts_desc, host, kind, action, path, file_name, extension, size,
       user_name, summary, source_id, row_no
FROM timeline
WHERE category = 'file';
