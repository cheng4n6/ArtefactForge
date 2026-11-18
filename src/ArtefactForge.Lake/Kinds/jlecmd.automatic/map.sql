-- JLECmd automatic destinations: one DestList entry per file an application opened. LastModified
-- is the entry's last use; CreationTime, when set and different, its first.
WITH j AS (
    SELECT r.*,
           coalesce(nullif(r.LocalPath, ''), nullif(r.Path, '')) AS target,
           lake_path_user(r.SourceFile) AS profile,
           coalesce(nullif(r.AppIdDescription, ''), r.AppId) AS app
    FROM raw_jlecmd_automatic r
),
times AS (
    SELECT j.*, lake_ts(LastModified) AS t_ts, LastModified AS t_raw, 'last_used' AS t_desc FROM j
    UNION ALL
    SELECT j.*, lake_ts(CreationTime), CreationTime, 'first_used' FROM j
    WHERE lake_ts(CreationTime) IS NOT NULL AND lake_ts(CreationTime) IS DISTINCT FROM lake_ts(LastModified)
)
SELECT
    t_ts                                                    AS ts,
    t_raw                                                   AS ts_raw,
    t_desc                                                  AS ts_desc,
    host,
    'windows'                                               AS platform,
    'jlecmd.automatic'                                      AS kind,
    'file'                                                  AS category,
    'open'                                                  AS action,
    profile                                                 AS user_name,
    target                                                  AS path,
    lake_file_name(target)                                  AS file_name,
    lake_extension(target)                                  AS extension,
    TRY_CAST(FileSize AS BIGINT)                            AS size,
    nullif(Arguments, '')                                   AS command_line,
    'Jump list (' || app || '): ' || coalesce(target, '?')
        || coalesce(', ' || nullif(InteractionCount, '') || ' interaction(s)', '') AS summary,
    source_id,
    row_no
FROM times
WHERE t_ts IS NOT NULL
