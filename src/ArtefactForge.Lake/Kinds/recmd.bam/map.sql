-- RECmd's BamDam plugin: the Background Activity Moderator's last run time of each program, per
-- user SID (the key's last part). Program is a device path, \Device\HarddiskVolume4\Windows\...,
-- shown without the volume as the other kinds do; packaged apps are a name, not a path.
SELECT
    lake_ts(ExecutionTime)                                  AS ts,
    ExecutionTime                                           AS ts_raw,
    'last_run'                                              AS ts_desc,
    host,
    'windows'                                               AS platform,
    'recmd.bam'                                             AS kind,
    'execution'                                             AS category,
    'run'                                                   AS action,
    nullif(regexp_extract(BatchKeyPath, '(S-1-[0-9-]+)$', 1), '') AS user_sid,
    lake_volume_path(Program)                               AS path,
    lake_file_name(Program)                                 AS file_name,
    lake_extension(Program)                                 AS extension,
    'BAM: ' || lake_volume_path(Program) || ' last ran' || coalesce(' (' || nullif(regexp_extract(BatchKeyPath, '(S-1-[0-9-]+)$', 1), '') || ')', '')
                                                            AS summary,
    source_id,
    row_no
FROM raw_recmd_bam
WHERE lake_ts(ExecutionTime) IS NOT NULL
