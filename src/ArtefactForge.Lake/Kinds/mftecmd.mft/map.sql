-- MFTECmd $MFT: a "created" row per file record, and a "modified" row when the content was
-- changed after it was created, both from $STANDARD_INFORMATION (0x10). Record change, access and
-- the $FILE_NAME (0x30) times stay in raw_mftecmd_mft: four or eight rows per file would bury the
-- timeline, and the times that matter for timestomping are compared there, not here.
-- ParentPath is ".\Users\alice" for a path from the volume root and "." for the root itself.
WITH f AS (
    SELECT r.*,
           CASE WHEN r.ParentPath IN ('.', '') THEN '\' || r.FileName
                WHEN starts_with(r.ParentPath, '.\') THEN substr(r.ParentPath, 2) || '\' || r.FileName
                ELSE r.ParentPath || '\' || r.FileName
           END AS full_path,
           TRY_CAST(r.Created0x10 AS TIMESTAMP)      AS created,
           TRY_CAST(r.LastModified0x10 AS TIMESTAMP) AS modified
    FROM raw_mftecmd_mft r
),
times AS (
    SELECT f.*, created AS t_ts, Created0x10 AS t_raw, 'created' AS t_desc, 'create' AS t_action FROM f
    UNION ALL
    SELECT f.*, modified, LastModified0x10, 'modified', 'modify' FROM f
    WHERE modified IS DISTINCT FROM created
)
SELECT
    t_ts                                                    AS ts,
    t_raw                                                   AS ts_raw,
    t_desc                                                  AS ts_desc,
    host,
    'windows'                                               AS platform,
    'mftecmd.mft'                                           AS kind,
    'file'                                                  AS category,
    t_action                                                AS action,
    full_path                                               AS path,
    FileName                                                AS file_name,
    CASE WHEN IsDirectory = 'True' THEN NULL
         ELSE nullif(lower(regexp_extract(FileName, '(\.[^.\\/ ]{1,10})$', 1)), '')
    END                                                     AS extension,
    TRY_CAST(FileSize AS BIGINT)                            AS size,
    concat_ws(' ', 'MFT', t_desc || ':', full_path,
              CASE WHEN IsDirectory = 'True' THEN '(folder)' END,
              CASE WHEN InUse = 'False' THEN '(deleted record)' END) AS summary,
    source_id,
    row_no
FROM times
WHERE t_ts IS NOT NULL
