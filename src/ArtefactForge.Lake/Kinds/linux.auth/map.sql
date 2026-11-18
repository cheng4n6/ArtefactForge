-- LinuxAuth events (auth.log, secure). A line with a zone has a UTC time (TimestampUtc). A
-- classic syslog line has none, only the host's local time (Timestamp): it is converted to UTC
-- with the host's time zone from outputs.json (host_zones), each line at its own date's offset,
-- and ts_desc says so and with which zone. A line with no usable zone stays in raw_linux_auth
-- and is counted against its source. _KeyEvents is a subset of this file and is kept raw.
WITH a AS (
    SELECT r.*,
           lake_ts(r.TimestampUtc) AS utc,
           CASE WHEN lake_ts(r.TimestampUtc) IS NULL THEN lake_local_utc(r.Timestamp, z.iana, z.fixed_offset) END AS converted,
           coalesce(z.iana, z.fixed_offset) AS zone
    FROM raw_linux_auth r
    LEFT JOIN host_zones z ON z.host = r.host
)
SELECT
    coalesce(utc, converted)                                AS ts,
    coalesce(nullif(RawTime, ''), nullif(TimestampUtc, ''), Timestamp) AS ts_raw,
    concat_ws(', ', CASE WHEN utc IS NULL THEN 'logged; converted from local time (' || zone || ')' ELSE 'logged' END,
              CASE WHEN YearInferred = 'yes' THEN 'year inferred' END) AS ts_desc,
    host,
    'linux'                                                 AS platform,
    'linux.auth'                                            AS kind,
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
FROM a
WHERE coalesce(utc, converted) IS NOT NULL
