-- title: Ransomware: the renames and files behind each host's verdict
-- category: ransomware
-- severity: critical
-- requires: ransomware_prepare
-- description: Every USN rename to the host's ransomware extension, every MFT file with it, and
--   every copy of the ransom note, in time order: the columns of ArtefactForge's
--   RansomwareEvidence.csv, with the host's Collection first. Times are UTC.
WITH e AS (
    SELECT collection, 'Renamed' AS kind, t AS ts, folder, new_name AS name, old_name AS previous_name,
           NULL::BIGINT AS size, NULL::BOOLEAN AS in_use, 'USN' AS source, 1 AS part, row_no
    FROM rw_hit_rename
    UNION ALL
    SELECT collection, 'Encrypted file', changed, folder, name, '', size, in_use, 'MFT', 2, row_no
    FROM rw_hit_file
    UNION ALL
    SELECT collection, 'Ransom note', created, folder, name, '', size, in_use, 'MFT', 3, row_no
    FROM rw_hit_note
)
SELECT collection AS "Collection",
       kind AS "Kind",
       coalesce(rw_fmt(ts), '') AS "TimeUtc",
       folder AS "Path",
       name AS "Name",
       previous_name AS "PreviousName",
       coalesce(size::VARCHAR, '') AS "Size",
       CASE WHEN in_use IS NULL THEN '' WHEN in_use THEN 'True' ELSE 'False' END AS "InUse",
       source AS "Source"
FROM e
ORDER BY upper(collection), collection, ts NULLS LAST, kind, part, row_no;
