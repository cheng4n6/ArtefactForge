-- LinuxSyslog_Events: one row per syslog line. As for auth logs, a line with only the host's
-- local time is converted to UTC with the host's time zone (each line at its own date's offset)
-- and ts_desc names the zone; without a usable zone it stays in raw_linux_syslog and is
-- counted. YearInferred says the line had no year and one was worked out from the file.
WITH s AS (
    SELECT r.*,
           lake_ts(r.TimestampUtc) AS utc,
           CASE WHEN lake_ts(r.TimestampUtc) IS NULL THEN lake_local_utc(r.Timestamp, z.iana, z.fixed_offset) END AS converted,
           coalesce(z.iana, z.fixed_offset) AS zone
    FROM raw_linux_syslog r
    LEFT JOIN host_zones z ON z.host = r.host
)
SELECT
    coalesce(utc, converted)                                AS ts,
    coalesce(nullif(RawTime, ''), nullif(TimestampUtc, ''), Timestamp) AS ts_raw,
    concat_ws(', ', CASE WHEN utc IS NULL THEN 'logged; converted from local time (' || zone || ')' ELSE 'logged' END,
              CASE WHEN YearInferred = 'yes' THEN 'year inferred' END) AS ts_desc,
    host,
    'linux'                                                 AS platform,
    'linux.syslog'                                          AS kind,
    'system'                                                AS category,
    nullif(Process, '')                                     AS process_path,
    TRY_CAST(PID AS BIGINT)                                 AS process_id,
    nullif(Log, '')                                         AS provider,
    concat_ws(': ', nullif(Process, ''), Message)           AS summary,
    source_id,
    row_no
FROM s
WHERE coalesce(utc, converted) IS NOT NULL
