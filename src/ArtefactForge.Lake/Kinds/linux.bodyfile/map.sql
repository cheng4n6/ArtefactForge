-- LinuxBodyfile_Timeline: one row per file per distinct time, with MACB saying which of
-- modified, accessed, changed (inode) and born that time is ("m.c." is modified and changed).
-- A birth time is a create; a modification a modify; the rest a change.
SELECT
    lake_ts(TimestampUtc)                                   AS ts,
    TimestampUtc                                            AS ts_raw,
    'macb ' || MACB                                         AS ts_desc,
    host,
    'linux'                                                 AS platform,
    'linux.bodyfile'                                        AS kind,
    'file'                                                  AS category,
    CASE WHEN contains(MACB, 'b') OR contains(MACB, 'B') THEN 'create'
         WHEN starts_with(MACB, 'm') OR starts_with(MACB, 'M') THEN 'modify'
         WHEN substr(MACB, 2, 1) IN ('a', 'A') AND substr(MACB, 3, 1) = '.' THEN 'access'
         ELSE 'change' END                                  AS action,
    nullif(User, '')                                        AS user_name,
    Path                                                    AS path,
    lake_file_name(Path)                                    AS file_name,
    CASE WHEN starts_with(Mode, 'd') THEN NULL ELSE lake_extension(Path) END AS extension,
    TRY_CAST(Size AS BIGINT)                                AS size,
    'bodyfile ' || MACB || ': ' || Path || coalesce(' -> ' || nullif(LinkTarget, ''), '') AS summary,
    source_id,
    row_no
FROM raw_linux_bodyfile
WHERE lake_ts(TimestampUtc) IS NOT NULL
