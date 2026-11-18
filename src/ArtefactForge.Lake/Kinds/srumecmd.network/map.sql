-- SrumECmd network usage: SRUM writes totals about once an hour, so each row is the bytes a
-- program sent and received over the interval ending at Timestamp, on one interface. ExeInfo is
-- a device path (\device\harddiskvolume4\...) or a service or app name.
SELECT
    lake_ts(Timestamp)                                      AS ts,
    Timestamp                                               AS ts_raw,
    'srum_interval'                                         AS ts_desc,
    host,
    'windows'                                               AS platform,
    'srumecmd.network'                                      AS kind,
    'network'                                               AS category,
    'transfer'                                              AS action,
    nullif(UserName, '')                                    AS user_name,
    nullif(Sid, '')                                         AS user_sid,
    lake_volume_path(ExeInfo)                               AS process_path,
    lake_file_name(ExeInfo)                                 AS file_name,
    TRY_CAST(BytesReceived AS BIGINT)                       AS bytes_in,
    TRY_CAST(BytesSent AS BIGINT)                           AS bytes_out,
    'SRUM network: ' || coalesce(nullif(ExeInfo, ''), '?') || ' sent ' || coalesce(BytesSent, '?')
        || ', received ' || coalesce(BytesReceived, '?') || ' bytes'
        || coalesce(' on ' || nullif(InterfaceType, ''), '') || coalesce(' (' || nullif(ProfileName, '') || ')', '') AS summary,
    source_id,
    row_no
FROM raw_srumecmd_network
WHERE lake_ts(Timestamp) IS NOT NULL
