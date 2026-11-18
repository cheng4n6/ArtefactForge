-- PECmd output: one row per Prefetch file, at its last run. Every run time, the last included,
-- is also in the timeline file (pecmd.timeline); this row adds the run count and the Prefetch
-- file. The program's path is the entry in FilesLoaded that ends with its name, with the
-- volume prefix dropped as in pecmd.timeline. Hash is Prefetch's hash of the path, not a file
-- hash, so it is not put in sha1.
WITH p AS (
    SELECT r.*,
           regexp_replace(
               list_filter(string_split(r.FilesLoaded, ', '),
                           lambda f: ends_with(upper(f), '\' || upper(r.ExecutableName)))[1],
               '^\\VOLUME\{[^}]*\}', '') AS image
    FROM raw_pecmd_output r
)
SELECT
    TRY_CAST(LastRun AS TIMESTAMP)                          AS ts,
    LastRun                                                 AS ts_raw,
    'last_run'                                              AS ts_desc,
    host,
    'windows'                                               AS platform,
    'pecmd.output'                                          AS kind,
    'execution'                                             AS category,
    'run'                                                   AS action,
    image                                                   AS path,
    nullif(ExecutableName, '')                              AS file_name,
    nullif(lower(regexp_extract(ExecutableName, '(\.[^.\\/ ]{1,10})$', 1)), '') AS extension,
    'Prefetch: ' || ExecutableName || ' last ran, run count ' || coalesce(RunCount, '?')
        || ' (' || SourceFilename || ')'                    AS summary,
    source_id,
    row_no
FROM p
WHERE TRY_CAST(LastRun AS TIMESTAMP) IS NOT NULL
