-- LinuxSyslog_Events: one row per syslog line. As for auth logs, a line with only the host's
-- local time stays in raw_linux_syslog and is counted against its source; YearInferred says
-- the line had no year and one was worked out from the file.
SELECT
    lake_ts(TimestampUtc)                                   AS ts,
    coalesce(nullif(RawTime, ''), TimestampUtc)             AS ts_raw,
    CASE WHEN YearInferred = 'yes' THEN 'logged_year_inferred' ELSE 'logged' END AS ts_desc,
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
FROM raw_linux_syslog
WHERE lake_ts(TimestampUtc) IS NOT NULL
