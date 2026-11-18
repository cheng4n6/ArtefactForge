-- AmcacheParser file entries: a program file Windows recorded, at the time its key was last
-- written (about when it was first seen or last changed; not proof it ran). SHA1 is the file's
-- first 31 MB hashed; older Amcache formats prefix it with four zeros, which are dropped.
SELECT
    lake_ts(FileKeyLastWriteTimestamp)                      AS ts,
    FileKeyLastWriteTimestamp                               AS ts_raw,
    'key_last_write'                                        AS ts_desc,
    host,
    'windows'                                               AS platform,
    'amcache.files'                                         AS kind,
    'execution'                                             AS category,
    'present'                                               AS action,
    nullif(FullPath, '')                                    AS path,
    coalesce(nullif(Name, ''), lake_file_name(FullPath))    AS file_name,
    coalesce(nullif(lower(FileExtension), ''), lake_extension(FullPath)) AS extension,
    TRY_CAST(Size AS BIGINT)                                AS size,
    CASE WHEN length(SHA1) = 44 AND starts_with(SHA1, '0000') THEN lower(substr(SHA1, 5))
         ELSE nullif(lower(SHA1), '')
    END                                                     AS sha1,
    concat_ws(' ', 'Amcache:', coalesce(nullif(FullPath, ''), nullif(Name, ''), 'SHA1 ' || lower(SHA1)),
              CASE WHEN nullif(ProductName, '') IS NOT NULL THEN '(' || ProductName || coalesce(' ' || nullif(Version, ''), '') || ')' END,
              CASE WHEN IsOsComponent = 'True' THEN '[OS component]' END) AS summary,
    source_id,
    row_no
FROM raw_amcache_files
WHERE lake_ts(FileKeyLastWriteTimestamp) IS NOT NULL
  AND (nullif(FullPath, '') IS NOT NULL OR nullif(SHA1, '') IS NOT NULL)
