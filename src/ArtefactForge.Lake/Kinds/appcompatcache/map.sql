-- AppCompatCacheParser (ShimCache): the time is the file's own last modified time as Windows
-- cached it, not when it ran. Executed is "Yes" only where Windows recorded it (Windows 7 and
-- some later builds); elsewhere it is "No" or "NA" and the entry shows the file was present.
-- Entries with no time (some Windows 10 entries) stay in raw_appcompatcache.
SELECT
    lake_ts(LastModifiedTimeUTC)                            AS ts,
    LastModifiedTimeUTC                                     AS ts_raw,
    'file_modified'                                         AS ts_desc,
    host,
    'windows'                                               AS platform,
    'appcompatcache'                                        AS kind,
    'execution'                                             AS category,
    CASE WHEN Executed = 'Yes' THEN 'run' ELSE 'present' END AS action,
    Path                                                    AS path,
    lake_file_name(Path)                                    AS file_name,
    lake_extension(Path)                                    AS extension,
    'ShimCache: ' || Path || ' (control set ' || ControlSet || ', position ' || CacheEntryPosition
        || ', executed ' || coalesce(nullif(Executed, ''), 'unknown') || ')' AS summary,
    source_id,
    row_no
FROM raw_appcompatcache
WHERE lake_ts(LastModifiedTimeUTC) IS NOT NULL
