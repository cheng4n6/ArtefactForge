-- PECmd timeline: every run time Prefetch recorded (up to eight per program). ExecutableName is
-- the full path on the volume, "\VOLUME{01d7...-7465b7bc}\PROGRAM FILES\7-ZIP\7ZFM.EXE"; the
-- volume prefix is dropped so the same program has the same path on every host. Some programs
-- have no path (Prefetch did not record one) and keep only the name.
WITH p AS (
    SELECT r.*,
           regexp_replace(r.ExecutableName, '^\\VOLUME\{[^}]*\}', '') AS image
    FROM raw_pecmd_timeline r
)
SELECT
    TRY_CAST(RunTime AS TIMESTAMP)                          AS ts,
    RunTime                                                 AS ts_raw,
    'executed'                                              AS ts_desc,
    host,
    'windows'                                               AS platform,
    'pecmd.timeline'                                        AS kind,
    'execution'                                             AS category,
    'run'                                                   AS action,
    CASE WHEN contains(image, '\') THEN image END           AS path,
    nullif(regexp_extract(image, '[^\\]+$'), '')            AS file_name,
    nullif(lower(regexp_extract(image, '(\.[^.\\/ ]{1,10})$', 1)), '') AS extension,
    'Prefetch: ' || image || ' ran'                         AS summary,
    source_id,
    row_no
FROM p
WHERE TRY_CAST(RunTime AS TIMESTAMP) IS NOT NULL
