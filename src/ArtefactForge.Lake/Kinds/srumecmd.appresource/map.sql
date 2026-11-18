-- SrumECmd application resource use: a program SRUM saw running in the interval ending at
-- Timestamp, with what it read from and wrote to disk (foreground plus background). Disk bytes
-- are not network bytes, so they go in the summary, not bytes_in and bytes_out.
SELECT
    lake_ts(Timestamp)                                      AS ts,
    Timestamp                                               AS ts_raw,
    'srum_interval'                                         AS ts_desc,
    host,
    'windows'                                               AS platform,
    'srumecmd.appresource'                                  AS kind,
    'execution'                                             AS category,
    'resource_use'                                          AS action,
    nullif(UserName, '')                                    AS user_name,
    nullif(Sid, '')                                         AS user_sid,
    lake_volume_path(ExeInfo)                               AS path,
    lake_file_name(ExeInfo)                                 AS file_name,
    lake_extension(ExeInfo)                                 AS extension,
    'SRUM app: ' || coalesce(nullif(ExeInfo, ''), '?') || ' read '
        || (coalesce(TRY_CAST(ForegroundBytesRead AS BIGINT), 0) + coalesce(TRY_CAST(BackgroundBytesRead AS BIGINT), 0))
        || ', wrote '
        || (coalesce(TRY_CAST(ForegroundBytesWritten AS BIGINT), 0) + coalesce(TRY_CAST(BackgroundBytesWritten AS BIGINT), 0))
        || ' bytes on disk'                                 AS summary,
    source_id,
    row_no
FROM raw_srumecmd_appresource
WHERE lake_ts(Timestamp) IS NOT NULL
