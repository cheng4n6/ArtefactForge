-- title: Ransomware: the case, one row per host, with where hosts differ
-- category: ransomware
-- severity: critical
-- requires: ransomware_prepare
-- description: The case's Ransomware.csv: every host's verdict, with Differences saying where a
--   host differs from what most hosts with a finding show (extension, note, note hash), and
--   where nothing was found on a host when it was on others.
WITH found AS (
    SELECT *, upper("Collection") || chr(0) || "Collection" AS ord FROM rw_host_row WHERE "Status" = 'Found'
),
found_count AS (SELECT count(*) AS n FROM found),
-- The value most hosts with a finding show; on a tie, the first in ordinal order.
common AS (
    SELECT field, value, hosts FROM (
        SELECT field, arg_min(value, ord) AS value, count(*) AS hosts
        FROM (
            SELECT 'extension' AS field, "Extension" AS value, ord FROM found
            UNION ALL SELECT 'note', "NoteName", ord FROM found
            UNION ALL SELECT 'note hash', "NoteSha256", ord FROM found
        )
        WHERE value <> ''
        GROUP BY field, lower(value)
    )
    QUALIFY row_number() OVER (PARTITION BY field ORDER BY hosts DESC, value) = 1
),
compared AS (
    SELECT r.*,
           concat_ws('; ',
               CASE WHEN r."Status" = 'None found' AND f.n > 0
                    THEN 'nothing found here, unlike ' || f.n || ' other host' || rw_s(f.n) END,
               CASE WHEN r."Status" = 'Found' AND ce.value IS NOT NULL AND lower(r."Extension") <> lower(ce.value) THEN
                    CASE WHEN r."Extension" = ''
                         THEN 'no extension found, unlike ' || ce.hosts || ' host' || rw_s(ce.hosts) || ' (' || ce.value || ')'
                         ELSE 'extension ' || r."Extension" || ' differs from ' || ce.value || ' on ' || ce.hosts || ' host' || rw_s(ce.hosts) END END,
               CASE WHEN r."Status" = 'Found' AND cn.value IS NOT NULL AND lower(r."NoteName") <> lower(cn.value) THEN
                    CASE WHEN r."NoteName" = ''
                         THEN 'no note found, unlike ' || cn.hosts || ' host' || rw_s(cn.hosts) || ' (' || cn.value || ')'
                         ELSE 'note ' || r."NoteName" || ' differs from ' || cn.value || ' on ' || cn.hosts || ' host' || rw_s(cn.hosts) END END,
               -- Only between saved copies: a host whose note could not be copied has no hash to compare.
               CASE WHEN r."Status" = 'Found' AND r."NoteSha256" <> '' AND ch.value IS NOT NULL
                         AND lower(r."NoteSha256") <> lower(ch.value)
                    THEN 'note hash ' || r."NoteSha256" || ' differs from ' || ch.value || ' on ' || ch.hosts || ' host' || rw_s(ch.hosts) END
           ) AS host_differences
    FROM rw_host_row r
    CROSS JOIN found_count f
    LEFT JOIN common ce ON ce.field = 'extension'
    LEFT JOIN common cn ON cn.field = 'note'
    LEFT JOIN common ch ON ch.field = 'note hash'
)
SELECT "Collection", "Host", "Status", "Extension", "ExtensionBasis", "NoteName", "NoteBasis", "NoteSize",
       "NoteSha256", "NoteCopy", "NoteFolders", "StartUtc", "StartIsEarliestSeen", "FinishUtc", "FilesAffected",
       "RatePerMinute", "PeakPerMinute", "Source", host_differences AS "Differences", "Detail"
FROM compared
ORDER BY "SortKey", "Collection";
