-- ArtefactForge's Autoruns batch for RECmd: one row per autostart value. The time is the key's
-- last write, which is when that key last changed, not necessarily when this value was added.
-- The command is ValueData; the user is the profile of the hive (an NTUSER.DAT under Users).
SELECT
    lake_ts(LastWriteTimestamp)                             AS ts,
    LastWriteTimestamp                                      AS ts_raw,
    'key_last_write'                                        AS ts_desc,
    host,
    'windows'                                               AS platform,
    'recmd.autoruns'                                        AS kind,
    'persistence'                                           AS category,
    CASE WHEN Deleted = 'True' THEN 'autorun_deleted' ELSE 'autorun' END AS action,
    lake_path_user(HivePath)                                AS user_name,
    nullif(ValueData, '')                                   AS command_line,
    KeyPath || coalesce('\' || nullif(ValueName, ''), '')   AS path,
    'Autorun (' || Description || '): ' || coalesce(nullif(ValueName, ''), '(default)')
        || coalesce(' = ' || nullif(ValueData, ''), '')     AS summary,
    source_id,
    row_no
FROM raw_recmd_autoruns
WHERE lake_ts(LastWriteTimestamp) IS NOT NULL
