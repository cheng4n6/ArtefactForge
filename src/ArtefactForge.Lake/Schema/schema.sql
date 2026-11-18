-- The evidence lake's fixed tables and views. The raw_<kind> tables are not here: each is created
-- from the columns of the first CSV loaded into it, and widened when a later file has more.

-- Helpers the mappings share, kept in the lake so a query can use them too.
-- A time as the tools write it: UTC, up to 7 fractional digits (DuckDB keeps 6).
CREATE MACRO lake_ts(x) AS TRY_CAST(x AS TIMESTAMP);
-- A time with an offset (Hayabusa's "2026-09-15 08:12:57.190 +00:00", Chainsaw's ISO 8601),
-- moved to UTC whatever the session's time zone; a time without one is taken as UTC.
CREATE MACRO lake_ts_offset(x) AS
    timezone('UTC', TRY_CAST(regexp_replace(x, '\s+([+-]\d\d:?\d\d|Z)$', '\1') AS TIMESTAMPTZ));
-- The last part of a Windows or Unix path.
CREATE MACRO lake_file_name(p) AS nullif(regexp_extract(p, '[^\\/]+$'), '');
-- A file name's extension in lower case with the dot; a long "extension" is not one.
CREATE MACRO lake_extension(n) AS nullif(lower(regexp_extract(n, '(\.[^.\\/ ]{1,10})$', 1)), '');
-- The profile a path is under: alice in C:\Users\alice\... or /home/alice/...
CREATE MACRO lake_path_user(p) AS
    nullif(coalesce(nullif(regexp_extract(p, '(?i)[\\/]Users[\\/]([^\\/]+)[\\/]', 1), ''),
                    regexp_extract(p, '^/home/([^/]+)/', 1)), '');
-- \Device\HarddiskVolume4\Windows\... and \VOLUME{...}\Windows\... as \Windows\...
-- A local time (no zone written) in UTC, from the host's IANA zone (its offset on that date) or
-- a fixed offset; null when there is neither. The year, if the log had none, is as given.
CREATE MACRO lake_local_utc(x, iana, fixed_offset) AS
    CASE WHEN iana IS NOT NULL THEN timezone('UTC', timezone(iana, TRY_CAST(x AS TIMESTAMP)))
         WHEN fixed_offset IS NOT NULL THEN timezone('UTC', TRY_CAST(x || fixed_offset AS TIMESTAMPTZ))
    END;
CREATE MACRO lake_volume_path(p) AS regexp_replace(p, '(?i)^\\(Device\\HarddiskVolume\d+|VOLUME\{[^}]*\})', '');

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
    mtime          TIMESTAMP,
    time_unread    BIGINT,            -- rows whose time the mapping could not read: raw only
    time_converted BIGINT             -- rows whose local time was converted to UTC with the host's zone
);

-- Each host's time zone as the lake can use it: an IANA name ("Europe/London"), which gives
-- each time its own offset across daylight saving changes, else a fixed offset ("+01:00",
-- "UTC-05:00"), else none. Windows zone names ("GMT Standard Time") are not IANA names and are
-- left out, so they never stand in for a zone they are not.
CREATE VIEW host_zones AS
SELECT h.host,
       h.time_zone,
       n.name AS iana,
       CASE WHEN n.name IS NULL
            -- Only a zone that is nothing but an offset ("+05:30", "UTC+05:30"): the offset after a
            -- named zone is the one in effect at one moment, wrong on the other side of a DST change.
            THEN nullif(regexp_extract(h.time_zone, '^\(?(?:UTC|GMT)?\s*([+-]\d\d:?\d\d)\)?$', 1), '')
       END AS fixed_offset
FROM hosts h
LEFT JOIN pg_timezone_names() n
       ON n.name = regexp_extract(h.time_zone, '^([A-Za-z]+(/[A-Za-z0-9_+-]+)+|UTC|GMT|Etc/[A-Za-z0-9+-]+)(\s|\(|$)', 1)
      AND h.time_zone NOT LIKE '% Time%';

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

-- Sigma and Hayabusa hits.
CREATE VIEW detections AS
SELECT ts, ts_raw, host, kind, rule_title, severity, event_id, channel, provider, summary, source_id, row_no
FROM timeline
WHERE category = 'detection';

-- Bytes each program sent and received, from SRUM: one row per program per interval.
CREATE VIEW network_usage AS
SELECT ts, host, user_name, user_sid, process_path, file_name AS program, bytes_in, bytes_out, summary,
       source_id, row_no
FROM timeline
WHERE kind = 'srumecmd.network';
