-- title: Web shells: scripts on an IIS server and the requests that used them
-- category: webshell
-- severity: high
-- description: Server scripts (.aspx, .ashx, .asmx, .asp ...) under a web site's folder, from the
--   MFT and USN journal, each with the IIS requests to it and the processes the IIS worker
--   (w3wp.exe) started within window_seconds of one of them. Listed when w3wp.exe started a
--   process after a request, when a request to it was flagged (web shell, Exchange exploit, a POST
--   to a script in a static folder), or when it sits in a folder that normally holds only static
--   files; and flagged POSTs answered 200 by a script no longer on disk. A lead to read, not a
--   verdict: a site's own scripts can match. Web roots come from IisLogs_Sites.csv, else
--   inetpub\wwwroot and Exchange's FrontEnd\HttpProxy.
-- files: iis_sites = WebLogs/IisLogs_Sites.csv (SiteId, SiteName, VirtualPath, CollectionPath)
-- table: raw_windows_iis (Flags)
-- parameter: window_seconds = 120 - how soon after a request a process w3wp.exe started counts as its child
-- parameter: script_extensions = .aspx,.ashx,.asmx,.asp,.cshtml,.php,.jsp - the file types a web server runs
WITH params AS (
    SELECT CAST(getvariable('window_seconds') AS INTEGER) AS window_s,
           list_transform(string_split(lower(getvariable('script_extensions')), ','), x -> trim(x)) AS exts
),
-- Each web root as a timeline path ("\inetpub\wwwroot", lower case) and the URL it serves at ("" for
-- the site root, "/downloads" for a virtual directory). A host without a site list gets the defaults.
listed AS (
    SELECT host, nullif(SiteName, '') AS site,
           lower(rtrim('\' || replace(ltrim(CollectionPath, '/\'), '/', '\'), '\')) AS root,
           rtrim(coalesce(VirtualPath, '/'), '/') AS vpath
    FROM iis_sites
    WHERE coalesce(CollectionPath, '') <> ''
),
roots AS (
    SELECT * FROM listed
    UNION ALL
    SELECT h.host, NULL, d.root, '' FROM hosts h
    CROSS JOIN (VALUES ('\inetpub\wwwroot'), ('\program files\microsoft\exchange server\v15\frontend\httpproxy')) AS d(root)
    WHERE NOT EXISTS (SELECT 1 FROM listed l WHERE l.host = h.host)
),
-- Script files as the MFT and USN journal record them: when each first appeared, and from which.
file_rows AS (
    SELECT t.host, t.path, lower(t.path) AS key, t.ts, t.action, t.kind
    FROM timeline t, params p
    WHERE t.category = 'file' AND t.kind IN ('mftecmd.mft', 'mftecmd.usnjournal')
      AND list_contains(p.exts, t.extension) AND t.path IS NOT NULL
),
scripts AS (
    SELECT host, key, arg_min(path, ts) AS path,
           min(ts) FILTER (WHERE action IN ('create', 'rename')) AS created,
           arg_min(CASE kind WHEN 'mftecmd.mft' THEN 'MFT' ELSE 'USN journal' END, ts) FILTER (WHERE action IN ('create', 'rename')) AS source
    FROM file_rows GROUP BY host, key
),
-- Each script under a web root, with the URL that runs it; the deepest root wins.
script_urls AS (
    SELECT s.*, r.site, lower(r.vpath || replace(substr(s.key, length(r.root) + 1), '\', '/')) AS stem
    FROM scripts s JOIN roots r ON r.host = s.host AND starts_with(s.key, r.root || '\')
    QUALIFY row_number() OVER (PARTITION BY s.host, s.key ORDER BY length(r.root) DESC) = 1
),
web AS (
    SELECT t.host, t.ts, lower(t.path) AS stem, t.url, t.http_method, t.http_status, t.src_ip, t.bytes_in,
           nullif(f.Flags, '') AS flags
    FROM timeline t LEFT JOIN raw_windows_iis f ON f.source_id = t.source_id AND f.row_no = t.row_no
    WHERE t.category = 'web' AND t.kind = 'windows.iis' AND t.path IS NOT NULL
),
requests AS (
    SELECT u.host, u.key, w.* EXCLUDE (host, stem)
    FROM script_urls u JOIN web w ON w.host = u.host AND w.stem = u.stem
),
-- What w3wp.exe started on the host within the window after a request to the script.
children AS (
    SELECT DISTINCT r.host, r.key, p.ts, p.file_name, p.source_id, p.row_no
    FROM requests r
    JOIN timeline p ON p.host = r.host AND p.category = 'process'
                   AND lower(p.parent_path) LIKE '%\w3wp.exe'
                   AND p.ts >= r.ts AND p.ts <= r.ts + to_seconds((SELECT window_s FROM params))
),
child_names AS (
    SELECT host, key, string_agg(name || ' (' || n || ')', ', ' ORDER BY first_ts, name) AS names, min(first_ts) AS first_ts,
           sum(n) AS total
    FROM (SELECT host, key, coalesce(file_name, '?') AS name, count(*) AS n, min(ts) AS first_ts FROM children GROUP BY ALL)
    GROUP BY host, key
),
per_script AS (
    SELECT u.host, u.key, any_value(u.site) AS site, any_value(u.path) AS path, any_value(u.stem) AS stem,
           any_value(u.created) AS created, any_value(u.source) AS source,
           min(r.ts) AS first_req, max(r.ts) AS last_req, count(r.ts) AS requests,
           count(*) FILTER (WHERE upper(r.http_method) = 'POST' AND r.http_status = 200) AS posts200,
           string_agg(DISTINCT r.src_ip, ', ' ORDER BY r.src_ip) AS clients,
           sum(r.bytes_in) AS bytes_in,
           string_agg(DISTINCT r.flags, '; ' ORDER BY r.flags) FILTER (WHERE r.flags IS NOT NULL) AS flags
    FROM script_urls u LEFT JOIN requests r ON r.host = u.host AND r.key = u.key
    GROUP BY u.host, u.key
),
candidates AS (
    SELECT s.*, c.names AS child_names, c.first_ts AS first_child, coalesce(c.total, 0) AS child_count,
           regexp_matches(s.key, '\\(aspnet_client|images?|img|uploads?|css|js|fonts|static|content|media)\\') AS static_folder
    FROM per_script s LEFT JOIN child_names c ON c.host = s.host AND c.key = s.key
),
found AS (
    SELECT host AS "Host", coalesce(site, '') AS "Site", path AS "ScriptPath", stem AS "Url",
           coalesce(strftime(created, '%Y-%m-%d %H:%M:%S'), '') AS "FileCreatedUtc", coalesce(source, '') AS "FileSource",
           coalesce(strftime(first_req, '%Y-%m-%d %H:%M:%S'), '') AS "FirstRequestUtc",
           coalesce(strftime(last_req, '%Y-%m-%d %H:%M:%S'), '') AS "LastRequestUtc",
           requests AS "Requests", posts200 AS "Posts200", coalesce(clients, '') AS "ClientIPs",
           coalesce(bytes_in, 0) AS "BytesReceived", coalesce(child_names, '') AS "ChildProcesses",
           coalesce(strftime(first_child, '%Y-%m-%d %H:%M:%S'), '') AS "FirstChildUtc",
           concat_ws('; ',
               CASE WHEN child_count > 0 THEN 'w3wp.exe started ' || child_count || ' process(es) within '
                    || (SELECT window_s FROM params) || ' s of a request to it' END,
               CASE WHEN flags IS NOT NULL THEN 'requests flagged ' || flags END,
               CASE WHEN static_folder THEN 'in a folder that normally holds only static files' END,
               CASE WHEN created IS NOT NULL AND first_req IS NOT NULL AND created > first_req
                    THEN 'file created after it was first requested: replaced?' END) AS "Detail",
           first_req AS sort_ts
    FROM candidates
    WHERE child_count > 0 OR flags IS NOT NULL OR static_folder
),
-- Flagged POSTs answered 200 by a script with no file in the MFT or journal: deleted since, or
-- on a volume the collection does not have.
gone AS (
    SELECT w.host AS "Host", '' AS "Site", '' AS "ScriptPath", any_value(w.stem) AS "Url", '' AS "FileCreatedUtc", '' AS "FileSource",
           strftime(min(w.ts), '%Y-%m-%d %H:%M:%S') AS "FirstRequestUtc", strftime(max(w.ts), '%Y-%m-%d %H:%M:%S') AS "LastRequestUtc",
           count(*) AS "Requests", count(*) AS "Posts200", string_agg(DISTINCT w.src_ip, ', ' ORDER BY w.src_ip) AS "ClientIPs",
           coalesce(sum(w.bytes_in), 0) AS "BytesReceived", '' AS "ChildProcesses", '' AS "FirstChildUtc",
           'requests flagged ' || string_agg(DISTINCT w.flags, '; ' ORDER BY w.flags)
               || '; no file for this URL in the MFT or USN journal: deleted, or not in the collection' AS "Detail",
           min(w.ts) AS sort_ts
    FROM web w, params p
    WHERE upper(w.http_method) = 'POST' AND w.http_status = 200 AND w.flags IS NOT NULL
      AND list_contains(p.exts, lower(regexp_extract(w.stem, '(\.[^./]+)$', 1)))
      AND NOT EXISTS (SELECT 1 FROM script_urls u WHERE u.host = w.host AND u.stem = w.stem)
    GROUP BY w.host, w.stem
)
SELECT * EXCLUDE (sort_ts) FROM (SELECT * FROM found UNION ALL SELECT * FROM gone)
ORDER BY sort_ts NULLS LAST, "Host", "Url"
