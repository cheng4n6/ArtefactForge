-- IisLogs_Requests: one row per request. _Flagged is the subset ArtefactForge marked (web shells,
-- Exchange exploits, scanners) and is kept raw; its Flags are on these rows too. Bytes are from the
-- server's side, as linux.weblogs: BytesSent out, BytesReceived in. Behind a load balancer ClientIP
-- is the balancer, so a logged X-Forwarded-For (its first address, the client's own) is the source.
-- The Host header column is csv_Host in the raw table, as the lake's own host column has that name.
SELECT
    lake_ts(TimestampUtc)                                   AS ts,
    coalesce(nullif(RawTime, ''), TimestampUtc)             AS ts_raw,
    'request'                                               AS ts_desc,
    host,
    'windows'                                               AS platform,
    'windows.iis'                                           AS kind,
    'web'                                                   AS category,
    'request'                                               AS action,
    nullif(CASE WHEN contains(User, '\') THEN split_part(User, '\', 2) ELSE User END, '')
                                                            AS user_name,
    CASE WHEN contains(User, '\') THEN nullif(split_part(User, '\', 1), '') END
                                                            AS user_domain,
    nullif(UriStem, '')                                     AS path,
    lake_file_name(nullif(UriStem, ''))                     AS file_name,
    lake_extension(lake_file_name(nullif(UriStem, '')))     AS extension,
    coalesce(nullif(trim(split_part(ForwardedFor, ',', 1)), ''), nullif(ClientIP, ''))
                                                            AS src_ip,
    nullif(ServerIP, '')                                    AS dst_ip,
    TRY_CAST(ServerPort AS INTEGER)                         AS dst_port,
    coalesce(nullif(csv_Host, ''), nullif(SiteName, ''))    AS domain,
    TRY_CAST(BytesReceived AS BIGINT)                       AS bytes_in,
    TRY_CAST(BytesSent AS BIGINT)                           AS bytes_out,
    Url                                                     AS url,
    nullif(Method, '')                                      AS http_method,
    TRY_CAST(Status AS INTEGER)                             AS http_status,
    nullif(UserAgent, '')                                   AS user_agent,
    concat_ws(' ', coalesce(nullif(SiteName, ''), 'site ' || SiteId) || ':', ClientIP, Method, Url, Status,
              CASE WHEN nullif(Flags, '') IS NOT NULL THEN '[' || Flags || ']' END) AS summary,
    source_id,
    row_no
FROM raw_windows_iis
WHERE lake_ts(TimestampUtc) IS NOT NULL
