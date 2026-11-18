-- LinuxJournal_Auth: the journal's auth events, classified as LinuxAuth's are, with a UTC time
-- from the journal itself. _KeyEvents is a subset and is kept raw.
SELECT
    lake_ts(TimestampUtc)                                   AS ts,
    TimestampUtc                                            AS ts_raw,
    'logged'                                                AS ts_desc,
    host,
    'linux'                                                 AS platform,
    'linux.journal_auth'                                    AS kind,
    CASE WHEN Event IN ('LoginSuccess', 'LoginFailed', 'InvalidUser', 'AuthFailure', 'SessionOpen', 'SessionClose', 'Disconnect')
              THEN 'logon'
         WHEN Event = 'SudoCommand' THEN 'process'
         WHEN Event IN ('AccountCreated', 'PasswordChanged') THEN 'account'
         ELSE 'system' END                                  AS category,
    CASE Event WHEN 'LoginSuccess' THEN 'logon_success' WHEN 'LoginFailed' THEN 'logon_fail'
               WHEN 'InvalidUser' THEN 'logon_fail' WHEN 'AuthFailure' THEN 'logon_fail'
               WHEN 'SessionOpen' THEN 'session_open' WHEN 'SessionClose' THEN 'logoff'
               WHEN 'Disconnect' THEN 'disconnect' WHEN 'SudoCommand' THEN 'run'
               WHEN 'AccountCreated' THEN 'create' WHEN 'PasswordChanged' THEN 'password_change'
               ELSE lower(nullif(Event, '')) END            AS action,
    nullif(User, '')                                        AS user_name,
    nullif(SourceIP, '')                                    AS src_ip,
    nullif(Process, '')                                     AS process_path,
    TRY_CAST(PID AS BIGINT)                                 AS process_id,
    nullif(Command, '')                                     AS command_line,
    concat_ws(': ', nullif(Event, ''), Message)             AS summary,
    source_id,
    row_no
FROM raw_linux_journal_auth
WHERE lake_ts(TimestampUtc) IS NOT NULL
