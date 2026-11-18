-- LinuxWebLogs_Access: one row per request. _Flagged is the subset ArtefactForge marked
-- (sensitive files, scanners, web shells) and is kept raw; its Flags are on these rows too.
-- Bytes is what the server sent back, so it is bytes_out from the server's side.
SELECT
    lake_ts(TimestampUtc)                                   AS ts,
    coalesce(nullif(RawTime, ''), TimestampUtc)             AS ts_raw,
    'request'                                               AS ts_desc,
    host,
    'linux'                                                 AS platform,
    'linux.weblogs'                                         AS kind,
    'web'                                                   AS category,
    'request'                                               AS action,
    nullif(nullif(User, ''), '-')                           AS user_name,
    nullif(ClientIP, '')                                    AS src_ip,
    nullif(VHost, '')                                       AS domain,
    Url                                                     AS url,
    nullif(Method, '')                                      AS http_method,
    TRY_CAST(Status AS INTEGER)                             AS http_status,
    TRY_CAST(nullif(Bytes, '-') AS BIGINT)                  AS bytes_out,
    nullif(nullif(UserAgent, ''), '-')                      AS user_agent,
    concat_ws(' ', Server || ':', ClientIP, Method, Url, Status, CASE WHEN nullif(Flags, '') IS NOT NULL THEN '[' || Flags || ']' END) AS summary,
    source_id,
    row_no
FROM raw_linux_weblogs
WHERE lake_ts(TimestampUtc) IS NOT NULL
