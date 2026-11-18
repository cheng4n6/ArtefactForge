-- JLECmd custom destinations: the items carry no times of their own, so each is placed at the
-- jump list file's last change. The target is the local path, else the shell item path.
WITH c AS (
    SELECT r.*,
           coalesce(nullif(r.LocalPath, ''), nullif(r.TargetIDAbsolutePath, '')) AS target,
           coalesce(nullif(r.AppIdDescription, ''), r.AppId) AS app
    FROM raw_jlecmd_custom r
)
SELECT
    lake_ts(SourceModified)                                 AS ts,
    SourceModified                                          AS ts_raw,
    'jumplist_modified'                                     AS ts_desc,
    host,
    'windows'                                               AS platform,
    'jlecmd.custom'                                         AS kind,
    'file'                                                  AS category,
    'open'                                                  AS action,
    lake_path_user(SourceFile)                              AS user_name,
    target                                                  AS path,
    lake_file_name(target)                                  AS file_name,
    lake_extension(target)                                  AS extension,
    nullif(Arguments, '')                                   AS command_line,
    'Jump list (' || app || '): ' || coalesce(nullif(EntryName, '') || ': ', '') || coalesce(target, '?') AS summary,
    source_id,
    row_no
FROM c
WHERE lake_ts(SourceModified) IS NOT NULL AND target IS NOT NULL
