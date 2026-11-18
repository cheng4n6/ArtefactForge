-- title: Data access: which artefacts each host had
-- category: data-access
-- requires: data_access_prepare
-- description: Every host's Sources.csv: each artefact the activity is read from, used or not
--   present, with the rows it gave and its files. Only hosts with at least one of them, and only
--   when CompromisedUsers.csv lists someone, as the activity is read only then.
WITH read_hosts AS (
    SELECT DISTINCT host FROM da_file WHERE EXISTS (SELECT 1 FROM da_compromised)
),
counted AS (
    SELECT host, input_ord, count(*) AS n FROM da_row GROUP BY host, input_ord
),
inputs AS (
    SELECT host, input_ord, string_agg(replace(path, '/', '\'), '; ' ORDER BY file_ord) AS files
    FROM da_file GROUP BY host, input_ord
)
SELECT h.collection AS "Collection", i.source AS "Source",
       CASE WHEN f.files IS NULL THEN 'not present: no ' || i.module || ' output' ELSE 'used' END AS "Status",
       CAST(coalesce(c.n, 0) AS VARCHAR) AS "Rows", coalesce(f.files, '') AS "Input"
FROM read_hosts r
JOIN da_host h ON h.collection = r.host
CROSS JOIN da_input i
LEFT JOIN inputs f ON f.host = r.host AND f.input_ord = i.input_ord
LEFT JOIN counted c ON c.host = r.host AND c.input_ord = i.input_ord
ORDER BY h.host_ord, i.input_ord;
