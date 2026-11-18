-- LinuxJournal_Entries: one row per journal entry. The journal records the process that logged
-- it (_EXE, _CMDLINE) and its unit, not what the message is about, so entries are 'system'.
SELECT
    lake_ts(TimestampUtc)                                   AS ts,
    TimestampUtc                                            AS ts_raw,
    'logged'                                                AS ts_desc,
    host,
    'linux'                                                 AS platform,
    'linux.journal'                                         AS kind,
    'system'                                                AS category,
    nullif(Priority, '')                                    AS severity,
    coalesce(nullif(Exe, ''), nullif(Comm, ''))             AS process_path,
    TRY_CAST(PID AS BIGINT)                                 AS process_id,
    nullif(CommandLine, '')                                 AS command_line,
    nullif(Unit, '')                                        AS provider,
    concat_ws(': ', coalesce(nullif(SyslogIdentifier, ''), nullif(Comm, '')), Message) AS summary,
    source_id,
    row_no
FROM raw_linux_journal
WHERE lake_ts(TimestampUtc) IS NOT NULL
