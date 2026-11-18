-- LinuxLogins wtmp and btmp: every btmp record is a failed logon; in wtmp USER_PROCESS is a
-- logon, DEAD_PROCESS a logoff and BOOT_TIME a boot. Host, the remote address or name, is
-- csv_Host in the raw table, as the lake's own host column has that name.
SELECT
    lake_ts(TimestampUtc)                                   AS ts,
    TimestampUtc                                            AS ts_raw,
    'logged'                                                AS ts_desc,
    host,
    'linux'                                                 AS platform,
    'linux.logins'                                          AS kind,
    CASE WHEN Type IN ('BOOT_TIME', 'RUN_LVL', 'SHUTDOWN_TIME') THEN 'system' ELSE 'logon' END AS category,
    CASE WHEN Source = 'btmp' THEN 'logon_fail'
         WHEN Type = 'USER_PROCESS' THEN 'logon_success'
         WHEN Type = 'DEAD_PROCESS' THEN 'logoff'
         WHEN Type = 'BOOT_TIME' THEN 'boot'
         ELSE lower(nullif(Type, '')) END                   AS action,
    nullif(User, '')                                        AS user_name,
    CASE WHEN regexp_matches(csv_Host, '^[0-9.]+$|:') THEN csv_Host END AS src_ip,
    CASE WHEN NOT regexp_matches(csv_Host, '^[0-9.]+$|:') THEN nullif(csv_Host, '') END AS domain,
    TRY_CAST(PID AS BIGINT)                                 AS process_id,
    concat_ws(' ', Source || ':', Type, nullif(User, ''), 'on ' || nullif(Terminal, ''), 'from ' || nullif(csv_Host, '')) AS summary,
    source_id,
    row_no
FROM raw_linux_logins
WHERE lake_ts(TimestampUtc) IS NOT NULL
