-- SBECmd ShellBags: a folder the user browsed in Explorer. FirstInteracted and LastInteracted
-- (from the bag's MRU) are the times it was used; a bag without them stays in raw_sbecmd, as
-- its other times describe the folder itself. The user comes from the hive's path when
-- SBECmd records it (SourceFile; a live registry run has none).
WITH s AS (
    SELECT r.*, lake_path_user(r.SourceFile) AS profile FROM raw_sbecmd r
),
times AS (
    SELECT s.*, lake_ts(LastInteracted) AS t_ts, LastInteracted AS t_raw, 'last_interacted' AS t_desc FROM s
    UNION ALL
    SELECT s.*, lake_ts(FirstInteracted), FirstInteracted, 'first_interacted' FROM s
    WHERE lake_ts(FirstInteracted) IS NOT NULL AND lake_ts(FirstInteracted) IS DISTINCT FROM lake_ts(LastInteracted)
)
SELECT
    t_ts                                                    AS ts,
    t_raw                                                   AS ts_raw,
    t_desc                                                  AS ts_desc,
    host,
    'windows'                                               AS platform,
    'sbecmd'                                                AS kind,
    'file'                                                  AS category,
    'browse'                                                AS action,
    profile                                                 AS user_name,
    AbsolutePath                                            AS path,
    lake_file_name(AbsolutePath)                            AS file_name,
    'ShellBag: ' || AbsolutePath || ' (' || ShellType || ')' AS summary,
    source_id,
    row_no
FROM times
WHERE t_ts IS NOT NULL
