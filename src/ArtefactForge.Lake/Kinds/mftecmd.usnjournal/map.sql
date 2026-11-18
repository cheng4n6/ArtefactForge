-- MFTECmd $J: one row per USN record. UpdateReasons is a '|' list ("DataExtend|FileCreate|Close");
-- action takes the most telling reason. ParentPath is only filled when $J was parsed with the
-- $MFT (-m), as ArtefactForge's module does; without it the path is the name alone.
WITH u AS (
    SELECT r.*,
           CASE WHEN coalesce(r.ParentPath, '') = '' THEN r.Name
                WHEN r.ParentPath = '.' THEN '\' || r.Name
                WHEN starts_with(r.ParentPath, '.\') THEN substr(r.ParentPath, 2) || '\' || r.Name
                ELSE r.ParentPath || '\' || r.Name
           END AS full_path
    FROM raw_mftecmd_usnjournal r
)
SELECT
    TRY_CAST(UpdateTimestamp AS TIMESTAMP)                  AS ts,
    UpdateTimestamp                                         AS ts_raw,
    'changed'                                               AS ts_desc,
    host,
    'windows'                                               AS platform,
    'mftecmd.usnjournal'                                    AS kind,
    'file'                                                  AS category,
    CASE
        WHEN contains(UpdateReasons, 'FileDelete') THEN 'delete'
        WHEN contains(UpdateReasons, 'FileCreate') THEN 'create'
        WHEN contains(UpdateReasons, 'RenameNewName') THEN 'rename'
        WHEN contains(UpdateReasons, 'RenameOldName') THEN 'rename_from'
        WHEN contains(UpdateReasons, 'DataOverwrite') OR contains(UpdateReasons, 'DataExtend')
             OR contains(UpdateReasons, 'DataTruncation') THEN 'modify'
        ELSE 'change'
    END                                                     AS action,
    full_path                                               AS path,
    Name                                                    AS file_name,
    CASE WHEN contains(FileAttributes, 'Directory') THEN NULL
         ELSE nullif(lower(Extension), '')
    END                                                     AS extension,
    'USN ' || UpdateReasons || ': ' || full_path            AS summary,
    source_id,
    row_no
FROM u
WHERE TRY_CAST(UpdateTimestamp AS TIMESTAMP) IS NOT NULL
