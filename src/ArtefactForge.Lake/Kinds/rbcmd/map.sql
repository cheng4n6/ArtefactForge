-- RBCmd: a file deleted to the Recycle Bin. FileName is its original path; the SID is the
-- $Recycle.Bin folder it sits in, which is the user who deleted it.
SELECT
    lake_ts(DeletedOn)                                      AS ts,
    DeletedOn                                               AS ts_raw,
    'deleted'                                               AS ts_desc,
    host,
    'windows'                                               AS platform,
    'rbcmd'                                                 AS kind,
    'file'                                                  AS category,
    'delete'                                                AS action,
    nullif(regexp_extract(SourceName, '(?i)\$Recycle\.Bin\\(S-1-[0-9-]+)\\', 1), '') AS user_sid,
    lake_path_user(FileName)                                AS user_name,
    FileName                                                AS path,
    lake_file_name(FileName)                                AS file_name,
    lake_extension(FileName)                                AS extension,
    TRY_CAST(FileSize AS BIGINT)                            AS size,
    'Recycle Bin: ' || FileName || ' deleted'               AS summary,
    source_id,
    row_no
FROM raw_rbcmd
WHERE lake_ts(DeletedOn) IS NOT NULL
