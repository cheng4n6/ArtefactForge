-- LinuxAudit_Events: one row per audit event (its records joined). An EXECVE record is a
-- command run; USER_LOGIN and USER_AUTH are logons; ADD_USER, DEL_USER, USER_CHAUTHTOK and the
-- group changes are account changes. AuditUser (auid) is who logged in, User who it ran as.
WITH a AS (
    SELECT r.*,
           CASE WHEN contains(r.RecordTypes, 'EXECVE') OR r.Syscall IN ('execve', 'execveat', '59', '322') THEN 'process'
                WHEN contains(r.RecordTypes, 'USER_LOGIN') OR contains(r.RecordTypes, 'USER_AUTH')
                     OR contains(r.RecordTypes, 'USER_START') OR contains(r.RecordTypes, 'USER_END') THEN 'logon'
                WHEN contains(r.RecordTypes, 'ADD_USER') OR contains(r.RecordTypes, 'DEL_USER')
                     OR contains(r.RecordTypes, 'USER_CHAUTHTOK') OR contains(r.RecordTypes, 'ADD_GROUP')
                     OR contains(r.RecordTypes, 'DEL_GROUP') OR contains(r.RecordTypes, 'USER_MGMT') THEN 'account'
                ELSE 'system' END AS cat
    FROM raw_linux_audit r
)
SELECT
    lake_ts(TimestampUtc)                                   AS ts,
    TimestampUtc                                            AS ts_raw,
    'logged'                                                AS ts_desc,
    host,
    'linux'                                                 AS platform,
    'linux.audit'                                           AS kind,
    cat                                                     AS category,
    CASE WHEN cat = 'process' THEN 'run'
         WHEN cat = 'logon' AND lower(coalesce(Result, Success, '')) IN ('success', 'yes') THEN 'logon_success'
         WHEN cat = 'logon' AND lower(coalesce(Result, Success, '')) IN ('failed', 'no') THEN 'logon_fail'
         ELSE nullif(lower(Operation), '') END              AS action,
    coalesce(nullif(Account, ''), nullif(AuditUser, ''), nullif(User, '')) AS user_name,
    CASE WHEN cat = 'process' THEN nullif(Exe, '') END      AS path,
    CASE WHEN cat = 'process' THEN lake_file_name(Exe) END  AS file_name,
    nullif(Exe, '')                                         AS process_path,
    TRY_CAST(PID AS BIGINT)                                 AS process_id,
    nullif(CommandLine, '')                                 AS command_line,
    nullif(nullif(Address, ''), '?')                        AS src_ip,
    concat_ws(' ', 'audit', RecordTypes || ':', coalesce(nullif(CommandLine, ''), nullif(Exe, ''), nullif(Operation, '')),
              CASE WHEN nullif(Key, '') IS NOT NULL THEN '[key ' || Key || ']' END) AS summary,
    source_id,
    row_no
FROM a
WHERE lake_ts(TimestampUtc) IS NOT NULL
