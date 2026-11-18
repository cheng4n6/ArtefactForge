-- LECmd: Windows writes a shortcut in Recent the first time a file is opened and updates it on
-- each later opening, so the LNK's own created time is the first opening and its modified time
-- the last. One row for each, the second only when it differs. The user is the profile the LNK
-- file sits in.
WITH l AS (
    SELECT r.*,
           coalesce(nullif(r.LocalPath, ''), nullif(r.NetworkPath, '')) AS target,
           lake_path_user(r.SourceFile) AS profile
    FROM raw_lecmd r
),
times AS (
    SELECT l.*, lake_ts(SourceCreated) AS t_ts, SourceCreated AS t_raw, 'first_opened' AS t_desc FROM l
    UNION ALL
    SELECT l.*, lake_ts(SourceModified), SourceModified, 'last_opened' FROM l
    WHERE lake_ts(SourceModified) IS DISTINCT FROM lake_ts(SourceCreated)
)
SELECT
    t_ts                                                    AS ts,
    t_raw                                                   AS ts_raw,
    t_desc                                                  AS ts_desc,
    host,
    'windows'                                               AS platform,
    'lecmd'                                                 AS kind,
    'file'                                                  AS category,
    'open'                                                  AS action,
    profile                                                 AS user_name,
    target                                                  AS path,
    lake_file_name(target)                                  AS file_name,
    lake_extension(target)                                  AS extension,
    TRY_CAST(FileSize AS BIGINT)                            AS size,
    nullif(Arguments, '')                                   AS command_line,
    concat_ws(' ', 'LNK:', coalesce(target, SourceFile), CASE WHEN nullif(MachineID, '') IS NOT NULL THEN '(on ' || MachineID || ')' END)
                                                            AS summary,
    source_id,
    row_no
FROM times
WHERE t_ts IS NOT NULL
