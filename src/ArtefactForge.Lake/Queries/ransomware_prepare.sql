-- title: Ransomware: working tables for the ransomware queries
-- category: ransomware
-- type: setup
-- description: Reads each host's MFTECmd $MFT and USN journal output and the analyst's
--   Ransomware-Overrides.csv into the temporary tables the ransomware queries share: the
--   extensions added to files, the ransom note candidates, and each host's verdict (rw_verdict).
--   The same rules and thresholds as ArtefactForge's Ransomware step, row for row.
-- input: ransomware_overrides = Ransomware-Overrides.csv (Collection, Extension, NoteName, Comment)
-- table: raw_mftecmd_mft (EntryNumber, SequenceNumber, InUse, ParentPath, FileName, FileSize, IsDirectory, IsAds, NameType, Created0x10, LastModified0x10, LastRecordChange0x10, SourceFile, ResidentDataBase64)
-- table: raw_mftecmd_usnjournal (Name, EntryNumber, SequenceNumber, ParentPath, UpdateTimestamp, UpdateReasons)
-- table: raw_unmapped_systeminfo (Category, Item, Value)
-- parameter: usn_min_files = 50 - renames adding one extension, outside system folders, before it is called
-- parameter: usn_min_folders = 5 - folders those renames are spread over
-- parameter: usn_min_types = 3 - file types (two renames each) the extension was added to
-- parameter: mft_min_files = 50 - files with the extension behind another one, outside system folders
-- parameter: mft_min_folders = 10 - folders those files are spread over
-- parameter: mft_min_types = 5 - file types (three files each) the extension follows
-- parameter: mft_min_share = 0.8 - share of all files with the extension that have it behind another
-- parameter: note_min_folders = 10 - folders holding a same-sized copy of a note

-- How the rules read, and why each is there, is on ArtefactForge.Core's RansomwareDetector; this
-- is the same decision in SQL. Names compare without regard to case, as Windows does; where the
-- C# kept the first spelling it met (a dictionary key), arg_min(x, row_no) does the same here.

-- MFTECmd's times, to the second ("2026-10-09 19:53:24.7804040"). They are UTC.
CREATE OR REPLACE TEMP MACRO rw_time(x) AS
    CASE WHEN length(x) >= 19 THEN try_strptime(trim(substr(x, 1, 19)), '%Y-%m-%d %H:%M:%S') END;
-- What follows the last dot, as .NET's Path.GetExtension without the dot; '' for none.
CREATE OR REPLACE TEMP MACRO rw_ext(n) AS coalesce(regexp_extract(n, '\.([^.\\/]+)$', 1), '');
-- A real file type before the added extension: one to five letters or digits, one a letter.
CREATE OR REPLACE TEMP MACRO rw_is_type(p) AS
    regexp_full_match(p, '[A-Za-z0-9]{1,5}') AND regexp_matches(p, '[A-Za-z]');
-- An extension that could be a ransomware one: a letter in it, no spaces, not absurdly long.
CREATE OR REPLACE TEMP MACRO rw_is_candidate(e) AS
    length(e) BETWEEN 1 AND 40 AND regexp_matches(e, '\pL') AND NOT regexp_matches(e, '[\s\pZ]');
-- Software keeps its own second-extension files here, and ransomware tends to leave them alone.
CREATE OR REPLACE TEMP MACRO rw_system_folder(f) AS
    starts_with(lower(f), '.\windows') OR starts_with(lower(f), '.\program files')
    OR starts_with(lower(f), '.\programdata') OR starts_with(lower(f), '.\$recycle.bin')
    OR contains(lower(f), '\appdata\') OR ends_with(lower(f), '\appdata');
-- What software adds or swaps in bulk as a matter of course. Never reported unless confirmed.
CREATE OR REPLACE TEMP MACRO rw_routine(e) AS lower(e) IN (
    'tmp', 'temp', 'old', 'bak', 'bk', 'backup', 'orig', 'prev', 'sav', 'save', 'new', 'partial', 'part',
    'crdownload', 'download', 'log', 'lock', 'swp', 'deleting', 'deletepending', 'vsctmp', 'af-old',
    'cache', 'etl', 'mui', 'map', 'config', 'manifest', 'cat', 'mum', 'gz', 'zip', '7z', 'sig', 'sha256',
    'md5', 'asc', 'meta', 'lnk', 'url', 'ini', 'dat');
CREATE OR REPLACE TEMP MACRO rw_note_ext(e) AS lower(e) IN ('txt', 'hta', 'html', 'htm', 'rtf', 'url', 'mht');
CREATE OR REPLACE TEMP MACRO rw_note_words(n) AS
    regexp_matches(lower(n), 'readme|read_me|read-me|decrypt|restore|recover|how_to|how-to|howto|ransom|instruction|unlock|encrypt|help_|_help|!!!');
-- The last folder of a path, as the C# LeafName.
CREATE OR REPLACE TEMP MACRO rw_leaf(f) AS
    CASE WHEN contains(rtrim(f, '\'), '\') THEN regexp_extract(rtrim(f, '\'), '[^\\]*$') ELSE f END;
-- "lockbit", ".LockBit" or " .lockbit " as ".lockbit"; empty stays empty.
CREATE OR REPLACE TEMP MACRO rw_normalise_ext(e) AS
    CASE WHEN ltrim(trim(e), '.') = '' THEN '' ELSE '.' || lower(ltrim(trim(e), '.')) END;
-- 1234 as "1,234", as the C# N0 writes it.
CREATE OR REPLACE TEMP MACRO rw_n0(n) AS format('{:,}', n);
CREATE OR REPLACE TEMP MACRO rw_fmt(t) AS strftime(t, '%Y-%m-%d %H:%M:%S');
-- 's' unless one.
CREATE OR REPLACE TEMP MACRO rw_s(n) AS CASE WHEN n = 1 THEN '' ELSE 's' END;

-- Where a query's output on the note copies goes; the lake build fills it.
CREATE TEMP TABLE IF NOT EXISTS ransomware_note_copies (
    collection VARCHAR, attempted BOOLEAN, note_sha256 VARCHAR, note_copy VARCHAR);

-- --- the analyst's overrides --------------------------------------------------------------------
-- A blank cell settles nothing (NULL); "none" or "-" says there is none (''). A row with no
-- collection, or "*", only adds its values to the sweep.
CREATE OR REPLACE TEMP TABLE rw_override AS
WITH o AS (
    SELECT input_row,
           trim(coalesce(Collection, '')) AS collection,
           trim(coalesce(Extension, ''))  AS ext_cell,
           trim(coalesce(NoteName, ''))   AS note_cell
    FROM ransomware_overrides
)
SELECT input_row, collection,
       CASE WHEN ext_cell = '' THEN NULL
            WHEN lower(ext_cell) = 'none' OR ext_cell = '-' THEN ''
            ELSE rw_normalise_ext(ext_cell) END AS ext,
       CASE WHEN note_cell = '' THEN NULL
            WHEN lower(note_cell) = 'none' OR note_cell = '-' THEN ''
            ELSE note_cell END AS note
FROM o;

-- Confirmed anywhere in the case, so looked for on every host, in the order the file gives them.
CREATE OR REPLACE TEMP TABLE rw_sweep_ext AS
SELECT ext, ltrim(ext, '.') AS bare, min(input_row) AS first_row
FROM rw_override WHERE ext <> '' GROUP BY ext;
CREATE OR REPLACE TEMP TABLE rw_sweep_note AS
SELECT lower(note) AS note_key, arg_min(note, input_row) AS note, min(input_row) AS first_row
FROM rw_override WHERE note <> '' GROUP BY lower(note);

-- --- hosts and their input ------------------------------------------------------------------------
-- The newest MFTECmd file of each kind in the host's FileSystem folder, as the C# step takes it.
CREATE OR REPLACE TEMP TABLE rw_host AS
WITH files AS (
    SELECT s.host, s.source_id, s.status, s.reason, s.mtime,
           CASE WHEN regexp_full_match(s.path, '(?i)FileSystem/MFTECmd_MFT[^/]*\.csv') THEN 'mft'
                WHEN regexp_full_match(s.path, '(?i)FileSystem/MFTECmd_USNJournal[^/]*\.csv') THEN 'usn' END AS which
    FROM sources s
),
newest AS (
    SELECT host, which, source_id, status, reason
    FROM files WHERE which IS NOT NULL
    QUALIFY row_number() OVER (PARTITION BY host, which ORDER BY mtime DESC NULLS LAST, source_id DESC) = 1
),
-- The machine's own name, from ArtefactForge's system summary as the C# step reads it (the last
-- Hostname with a value), else outputs.json, else the folder.
system_name AS (
    SELECT r.host, arg_max(r.Value, r.row_no) AS hostname
    FROM raw_unmapped_systeminfo r JOIN sources s ON s.source_id = r.source_id
    WHERE lower(s.path) = 'systeminfo/systeminfo.csv' AND lower(r.Item) = 'hostname' AND coalesce(r.Value, '') <> ''
    GROUP BY r.host
)
SELECT h.host AS collection,
       coalesce(sn.hostname, nullif(h.hostname, ''), h.host) AS host_name,
       m.source_id AS mft_source, m.status AS mft_status, m.reason AS mft_reason,
       u.source_id AS usn_source, u.status AS usn_status, u.reason AS usn_reason
FROM hosts h
LEFT JOIN newest m ON m.host = h.host AND m.which = 'mft'
LEFT JOIN newest u ON u.host = h.host AND u.which = 'usn'
LEFT JOIN system_name sn ON sn.host = h.host;

-- What the overrides say about each host: its own rows (a later one wins), and the key that
-- records them with the result.
CREATE OR REPLACE TEMP TABLE rw_hints AS
SELECT h.collection,
       (SELECT arg_max(o.ext, o.input_row) FROM rw_override o
         WHERE o.ext IS NOT NULL AND (lower(o.collection) = lower(h.collection) OR lower(o.collection) = lower(h.host_name))) AS own_ext,
       (SELECT arg_max(o.note, o.input_row) FROM rw_override o
         WHERE o.note IS NOT NULL AND (lower(o.collection) = lower(h.collection) OR lower(o.collection) = lower(h.host_name))) AS own_note
FROM rw_host h;

CREATE OR REPLACE TEMP TABLE rw_parameters AS
SELECT h.collection,
       'v1;ext=' || coalesce(h.own_ext, '-') || ';note=' || coalesce(h.own_note, '-')
       || ';sweepExt=' || coalesce((SELECT string_agg(ext, '|' ORDER BY ext) FROM rw_sweep_ext), '')
       || ';sweepNote=' || coalesce((SELECT string_agg(note, '|' ORDER BY note) FROM rw_sweep_note), '') AS parameters
FROM rw_hints h;

-- --- the MFT --------------------------------------------------------------------------------------
-- Files only, and each once: no folders, no alternate data streams, no 8.3 twin of a long name.
CREATE OR REPLACE TEMP TABLE rw_mft_row AS
SELECT h.collection, r.row_no,
       coalesce(r.ParentPath, '') AS folder,
       coalesce(r.FileName, '')   AS name,
       coalesce(TRY_CAST(r.FileSize AS BIGINT), 0) AS size,
       lower(coalesce(r.InUse, '')) <> 'false' AS in_use,
       rw_time(r.Created0x10) AS created,
       coalesce(rw_time(r.LastRecordChange0x10), rw_time(r.LastModified0x10)) AS changed,
       coalesce(r.ResidentDataBase64, '') AS resident,
       string_split(coalesce(r.FileName, ''), '.') AS parts
FROM raw_mftecmd_mft r
JOIN rw_host h ON r.source_id = h.mft_source
WHERE lower(coalesce(r.IsDirectory, '')) <> 'true'
  AND lower(coalesce(r.IsAds, '')) <> 'true'
  AND lower(coalesce(r.NameType, '')) <> 'dos';

CREATE OR REPLACE TEMP TABLE rw_mft_file AS
SELECT m.* EXCLUDE (parts),
       CASE WHEN len(parts) >= 2 THEN parts[-1] ELSE '' END AS ext,
       CASE WHEN len(parts) >= 3 THEN list_filter(parts[2:len(parts) - 1], p -> rw_is_type(p))[1] END AS added_to,
       rw_system_folder(m.folder) AS system_folder
FROM rw_mft_row m;

-- Every file with each extension: the share's denominator.
CREATE OR REPLACE TEMP TABLE rw_mft_total AS
SELECT collection, lower(ext) AS ext_key, count(*) AS files
FROM rw_mft_file WHERE ext <> '' GROUP BY collection, lower(ext);

-- Files with an extension behind another one, or with one confirmed in the overrides.
CREATE OR REPLACE TEMP TABLE rw_mft_ext AS
SELECT f.*, lower(f.ext) AS ext_key
FROM rw_mft_file f
WHERE f.ext <> ''
  AND ((f.added_to IS NOT NULL AND rw_is_candidate(f.ext)) OR lower(f.ext) IN (SELECT bare FROM rw_sweep_ext));

-- The most of an extension's files changed inside any one 24 hours.
CREATE OR REPLACE TEMP TABLE rw_mft_window AS
SELECT collection, ext_key, max(n) AS most
FROM (SELECT collection, ext_key,
             count(*) OVER (PARTITION BY collection, ext_key ORDER BY changed
                            RANGE BETWEEN INTERVAL 24 HOURS PRECEDING AND CURRENT ROW) AS n
      FROM rw_mft_ext WHERE changed IS NOT NULL)
GROUP BY collection, ext_key;

-- The types an extension follows, outside the system folders.
CREATE OR REPLACE TEMP TABLE rw_mft_type AS
SELECT collection, ext_key, lower(added_to) AS type, count(*) AS n
FROM rw_mft_ext WHERE NOT system_folder AND added_to IS NOT NULL
GROUP BY collection, ext_key, lower(added_to);

CREATE OR REPLACE TEMP TABLE rw_mft_stats AS
SELECT e.collection, e.ext_key,
       arg_min(e.ext, e.row_no) AS ext,
       count(*) AS files,
       count(*) FILTER (WHERE NOT e.system_folder) AS user_files,
       count(DISTINCT lower(e.folder)) FILTER (WHERE NOT e.system_folder) AS folders,
       min(e.row_no) AS first_row
FROM rw_mft_ext e GROUP BY e.collection, e.ext_key;

-- --- the USN journal -----------------------------------------------------------------------------
CREATE OR REPLACE TEMP TABLE rw_usn_row AS
SELECT h.collection, r.row_no,
       coalesce(r.Name, '') AS name,
       coalesce(r.EntryNumber, '') || '-' || coalesce(r.SequenceNumber, '') AS key,
       rw_time(r.UpdateTimestamp) AS t,
       coalesce(r.UpdateReasons, '') AS reasons,
       coalesce(r.ParentPath, '') AS folder
FROM raw_mftecmd_usnjournal r
JOIN rw_host h ON r.source_id = h.usn_source;

CREATE OR REPLACE TEMP TABLE rw_usn_start AS
SELECT collection, min(t) AS journal_start FROM rw_usn_row GROUP BY collection;

-- A rename is an old-name record followed by a new-name record of the same file (MFT entry and
-- sequence), with nothing of either kind between them.
CREATE OR REPLACE TEMP TABLE rw_usn_rename AS
WITH e AS (
    SELECT *, CASE WHEN contains(reasons, 'RenameOldName') THEN 'O'
                   WHEN contains(reasons, 'RenameNewName') THEN 'N' END AS step
    FROM rw_usn_row
),
paired AS (
    SELECT *, lag(step) OVER w AS prev_step, lag(name) OVER w AS old_name
    FROM e WHERE step IS NOT NULL
    WINDOW w AS (PARTITION BY collection, key ORDER BY row_no)
),
renames AS (
    SELECT collection, row_no, key, t, folder, old_name, name AS new_name,
           rw_ext(name) AS ext, rw_ext(old_name) AS old_ext
    FROM paired WHERE step = 'N' AND prev_step = 'O'
)
SELECT r.*, lower(r.ext) AS ext_key, rw_system_folder(r.folder) AS system_folder
FROM renames r
WHERE r.ext <> ''
  AND ((length(r.new_name) > length(r.old_name) + 1 AND starts_with(lower(r.new_name), lower(r.old_name || '.'))
        AND rw_is_candidate(r.ext))
       OR (lower(r.ext) IN (SELECT bare FROM rw_sweep_ext) AND lower(r.old_ext) <> lower(r.ext)));

CREATE OR REPLACE TEMP TABLE rw_usn_type AS
SELECT collection, ext_key, lower(old_ext) AS type, count(*) AS n
FROM rw_usn_rename WHERE NOT system_folder AND rw_is_type(old_ext)
GROUP BY collection, ext_key, lower(old_ext);

CREATE OR REPLACE TEMP TABLE rw_usn_stats AS
SELECT collection, ext_key,
       arg_min(ext, row_no) AS ext,
       count(DISTINCT key) AS files,
       count(*) FILTER (WHERE NOT system_folder) AS user_files,
       count(DISTINCT lower(folder)) FILTER (WHERE NOT system_folder) AS folders
FROM rw_usn_rename GROUP BY collection, ext_key;

-- --- extension candidates ------------------------------------------------------------------------
-- At least this many types with this many files each, and none more than three quarters of them.
CREATE OR REPLACE TEMP MACRO rw_varied(total, typed, biggest, types) AS
    total > 0 AND typed >= types AND biggest < total * 0.75;

CREATE OR REPLACE TEMP TABLE rw_candidate AS
WITH usn_types AS (
    SELECT collection, ext_key, sum(n) AS total, count(*) FILTER (WHERE n >= 2) AS typed, max(n) AS biggest
    FROM rw_usn_type GROUP BY collection, ext_key
),
mft_types AS (
    SELECT collection, ext_key, sum(n) AS total, count(*) FILTER (WHERE n >= 3) AS typed, max(n) AS biggest
    FROM rw_mft_type GROUP BY collection, ext_key
),
usn AS (
    SELECT s.collection, s.ext_key, s.ext, s.files
    FROM rw_usn_stats s JOIN usn_types t USING (collection, ext_key)
    WHERE NOT rw_routine(s.ext) AND s.user_files >= getvariable('usn_min_files')::INTEGER
      AND s.folders >= getvariable('usn_min_folders')::INTEGER
      AND rw_varied(t.total, t.typed, t.biggest, getvariable('usn_min_types')::INTEGER)
),
mft AS (
    SELECT s.collection, s.ext_key, s.ext, s.files
    FROM rw_mft_stats s
    JOIN mft_types t USING (collection, ext_key)
    JOIN rw_mft_total a USING (collection, ext_key)
    LEFT JOIN rw_mft_window w USING (collection, ext_key)
    WHERE NOT rw_routine(s.ext) AND s.user_files >= getvariable('mft_min_files')::INTEGER
      AND s.folders >= getvariable('mft_min_folders')::INTEGER
      AND rw_varied(t.total, t.typed, t.biggest, getvariable('mft_min_types')::INTEGER)
      AND s.files >= a.files * getvariable('mft_min_share')::DOUBLE
      -- Encryption runs in hours; a browser's resilience copies pass every count above over months.
      AND coalesce(w.most, 0) >= s.files * 0.5
),
merged AS (
    SELECT coalesce(u.collection, m.collection) AS collection,
           coalesce(u.ext_key, m.ext_key) AS ext_key,
           coalesce(u.ext, m.ext) AS ext,
           greatest(coalesce(u.files, 0), coalesce(m.files, 0)) AS files
    FROM usn u FULL JOIN mft m USING (collection, ext_key)
)
SELECT *, row_number() OVER (PARTITION BY collection ORDER BY files DESC, ext) AS rank
FROM merged;

-- --- the extension each host is given -------------------------------------------------------------
CREATE OR REPLACE TEMP TABLE rw_extension AS
WITH top AS (SELECT * FROM rw_candidate WHERE rank = 1),
others AS (
    SELECT collection,
           'other candidate extensions: '
           || string_agg('.' || ext || ' (' || rw_n0(files) || ' files)', ', ' ORDER BY rank) AS detail
    FROM rw_candidate WHERE rank BETWEEN 2 AND 6 GROUP BY collection
),
swept AS (
    SELECT h.collection, s.ext,
           row_number() OVER (PARTITION BY h.collection
                              ORDER BY greatest(coalesce(u.files, 0), coalesce(m.files, 0)) DESC, s.first_row) AS pick,
           greatest(coalesce(u.files, 0), coalesce(m.files, 0)) AS files
    FROM rw_host h CROSS JOIN rw_sweep_ext s
    LEFT JOIN rw_usn_stats u ON u.collection = h.collection AND u.ext_key = s.bare
    LEFT JOIN rw_mft_stats m ON m.collection = h.collection AND m.ext_key = s.bare
)
SELECT h.collection, h.own_ext,
       CASE WHEN h.own_ext IS NOT NULL THEN h.own_ext
            WHEN t.ext IS NOT NULL THEN '.' || t.ext
            WHEN sw.ext IS NOT NULL THEN sw.ext
            ELSE '' END AS extension,
       CASE WHEN h.own_ext IS NOT NULL THEN
                CASE WHEN h.own_ext = '' THEN ''
                     WHEN t.ext IS NOT DISTINCT FROM ltrim(h.own_ext, '.') THEN 'Confirmed' ELSE 'Override' END
            WHEN t.ext IS NOT NULL THEN 'Detected'
            WHEN sw.ext IS NOT NULL THEN 'Swept'
            ELSE '' END AS basis,
       CASE WHEN h.own_ext IS NULL AND t.ext IS NOT NULL THEN o.detail END AS others_detail
FROM rw_hints h
LEFT JOIN top t ON t.collection = h.collection
LEFT JOIN others o ON o.collection = h.collection
LEFT JOIN swept sw ON sw.collection = h.collection AND sw.pick = 1 AND sw.files > 0;

-- The renames and files behind each host's extension, and what they say about when.
CREATE OR REPLACE TEMP TABLE rw_hit_rename AS
SELECT r.* FROM rw_usn_rename r JOIN rw_extension e
  ON e.collection = r.collection AND e.extension <> '' AND r.ext_key = lower(ltrim(e.extension, '.'));
CREATE OR REPLACE TEMP TABLE rw_hit_file AS
SELECT f.* FROM rw_mft_ext f JOIN rw_extension e
  ON e.collection = f.collection AND e.extension <> '' AND f.ext_key = lower(ltrim(e.extension, '.'));

CREATE OR REPLACE TEMP TABLE rw_encrypted_folder AS
SELECT DISTINCT collection, lower(folder) AS folder FROM rw_hit_file
UNION
SELECT DISTINCT collection, lower(folder) FROM rw_hit_rename;

CREATE OR REPLACE TEMP TABLE rw_times AS
WITH usn AS (
    SELECT collection, count(DISTINCT key) AS files, min(t) AS first_t, max(t) AS last_t,
           arg_min(old_name, row_no) AS sample_old, arg_min(new_name, row_no) AS sample_new, count(*) AS renames
    FROM rw_hit_rename GROUP BY collection
),
usn_peak AS (
    SELECT collection, max(n) AS peak FROM (
        SELECT collection, count(*) AS n FROM rw_hit_rename WHERE t IS NOT NULL
        GROUP BY collection, date_trunc('minute', t)) GROUP BY collection
),
mft AS (
    SELECT collection, count(*) AS files, min(changed) AS first_t, max(changed) AS last_t
    FROM rw_hit_file GROUP BY collection
),
mft_peak AS (
    SELECT collection, max(n) AS peak FROM (
        SELECT collection, count(*) AS n FROM rw_hit_file WHERE changed IS NOT NULL
        GROUP BY collection, date_trunc('minute', changed)) GROUP BY collection
)
SELECT e.collection, e.extension,
       coalesce(u.files, 0) AS usn_files, coalesce(m.files, 0) AS mft_files,
       u.first_t AS usn_first, u.last_t AS usn_last, up.peak AS usn_peak,
       m.first_t AS mft_first, m.last_t AS mft_last, mp.peak AS mft_peak,
       u.sample_old, u.sample_new, coalesce(u.renames, 0) AS renames
FROM rw_extension e
LEFT JOIN usn u USING (collection)
LEFT JOIN usn_peak up USING (collection)
LEFT JOIN mft m USING (collection)
LEFT JOIN mft_peak mp USING (collection)
WHERE e.extension <> '';

-- --- the note ---------------------------------------------------------------------------------------
-- Note-like files: a note's extension at a note's size, or a name confirmed in the overrides.
CREATE OR REPLACE TEMP TABLE rw_note_copy AS
SELECT f.collection, f.row_no, f.folder, f.name, lower(f.name) AS name_key, f.size, f.in_use, f.created, f.resident
FROM rw_mft_file f
WHERE lower(f.name) IN (SELECT note_key FROM rw_sweep_note)
   OR (rw_note_ext(f.ext) AND f.size BETWEEN 16 AND 1048576);

-- The size most copies of each name have; on a tie, the size met first.
CREATE OR REPLACE TEMP TABLE rw_note_size AS
SELECT collection, name_key, size
FROM rw_note_copy
GROUP BY collection, name_key, size
QUALIFY row_number() OVER (PARTITION BY collection, name_key ORDER BY count(*) DESC, min(row_no)) = 1;

CREATE OR REPLACE TEMP TABLE rw_note_name AS
WITH copies AS (
    SELECT collection, name_key, count(*) AS copies, arg_min(name, row_no) AS key_name, min(row_no) AS first_row
    FROM rw_note_copy GROUP BY collection, name_key
),
same AS (
    SELECT c.collection, c.name_key, count(*) AS same, arg_min(c.name, c.row_no) AS same_name,
           count(DISTINCT lower(rw_leaf(c.folder))) AS leaves,
           count(*) FILTER (WHERE x.folder IS NOT NULL) AS with_encrypted
    FROM rw_note_copy c JOIN rw_note_size s USING (collection, name_key)
    LEFT JOIN rw_encrypted_folder x ON x.collection = c.collection AND x.folder = lower(c.folder)
    WHERE c.size = s.size
    GROUP BY c.collection, c.name_key
),
created AS (
    SELECT collection, name_key, max(n) AS most FROM (
        SELECT c.collection, c.name_key,
               count(*) OVER (PARTITION BY c.collection, c.name_key ORDER BY c.created
                              RANGE BETWEEN INTERVAL 6 HOURS PRECEDING AND CURRENT ROW) AS n
        FROM rw_note_copy c JOIN rw_note_size s USING (collection, name_key)
        WHERE c.size = s.size AND c.created IS NOT NULL)
    GROUP BY collection, name_key
)
SELECT c.collection, c.name_key, c.key_name, c.copies, c.first_row, s.size, m.same, m.same_name, m.leaves,
       m.with_encrypted >= m.same * 0.5 AS beside_files,
       rw_note_words(c.key_name) AS reads,
       c.copies >= getvariable('note_min_folders')::INTEGER
       AND m.same >= c.copies * 0.9 AND m.same >= getvariable('note_min_folders')::INTEGER
       AND s.size BETWEEN 16 AND 1048576
       AND rw_note_ext(rw_ext(c.key_name))
       AND coalesce(w.most, 0) >= m.same * 0.9
       -- The same package installed many times puts a file in many folders of one name.
       AND m.leaves >= m.same * 0.5
       AND (m.with_encrypted >= m.same * 0.5 OR rw_note_words(c.key_name)) AS qualifies
FROM copies c
JOIN rw_note_size s USING (collection, name_key)
JOIN same m USING (collection, name_key)
LEFT JOIN created w USING (collection, name_key);

CREATE OR REPLACE TEMP TABLE rw_note_detected AS
SELECT collection, name_key, same_name, size FROM (
    SELECT *, row_number() OVER (PARTITION BY collection
                                 ORDER BY same * (CASE WHEN beside_files THEN 10 ELSE 1 END) * (CASE WHEN reads THEN 2 ELSE 1 END) DESC,
                                          first_row) AS pick
    FROM rw_note_name WHERE qualifies)
WHERE pick = 1;

CREATE OR REPLACE TEMP TABLE rw_note AS
WITH swept AS (
    SELECT h.collection, n.collection IS NOT NULL AS found, n.name_key, n.key_name, n.size,
           row_number() OVER (PARTITION BY h.collection ORDER BY n.copies DESC, s.first_row) AS pick
    FROM rw_host h CROSS JOIN rw_sweep_note s
    JOIN rw_note_name n ON n.collection = h.collection AND n.name_key = s.note_key
)
SELECT h.collection,
       CASE WHEN rh.mft_source IS NULL THEN NULL
            WHEN h.own_note = '' THEN NULL
            WHEN h.own_note IS NOT NULL THEN lower(h.own_note)
            WHEN d.name_key IS NOT NULL THEN d.name_key
            ELSE sw.name_key END AS name_key,
       CASE WHEN rh.mft_source IS NULL OR h.own_note = '' THEN ''
            WHEN h.own_note IS NOT NULL THEN coalesce(own.key_name, h.own_note)
            WHEN d.name_key IS NOT NULL THEN d.same_name
            ELSE coalesce(sw.key_name, '') END AS note_name,
       CASE WHEN rh.mft_source IS NULL OR h.own_note = '' THEN ''
            WHEN h.own_note IS NOT NULL THEN CASE WHEN lower(d.name_key) = lower(h.own_note) THEN 'Confirmed' ELSE 'Override' END
            WHEN d.name_key IS NOT NULL THEN 'Detected'
            WHEN sw.name_key IS NOT NULL THEN 'Swept'
            ELSE '' END AS basis,
       CASE WHEN rh.mft_source IS NULL OR h.own_note = '' THEN NULL
            WHEN h.own_note IS NOT NULL THEN coalesce(own.size, 0)
            WHEN d.name_key IS NOT NULL THEN d.size
            ELSE sw.size END AS size
FROM rw_hints h
JOIN rw_host rh USING (collection)
LEFT JOIN rw_note_detected d USING (collection)
LEFT JOIN rw_note_name own ON own.collection = h.collection AND own.name_key = lower(h.own_note)
LEFT JOIN swept sw ON sw.collection = h.collection AND sw.pick = 1;

CREATE OR REPLACE TEMP TABLE rw_hit_note AS
SELECT c.* FROM rw_note_copy c JOIN rw_note n
  ON n.collection = c.collection AND n.name_key IS NOT NULL AND c.name_key = n.name_key;

-- --- each host's verdict -----------------------------------------------------------------------------
CREATE OR REPLACE TEMP TABLE rw_verdict AS
WITH note_stats AS (
    SELECT collection, count(DISTINCT lower(folder)) AS folders, min(created) AS first_created,
           max(created) AS last_created, arg_min(folder, row_no) AS first_folder, arg_min(name, row_no) AS first_name
    FROM rw_hit_note GROUP BY collection
),
mft_root AS (
    SELECT h.collection, arg_min(r.SourceFile, r.row_no) AS source_file
    FROM raw_mftecmd_mft r JOIN rw_host h ON r.source_id = h.mft_source
    WHERE coalesce(r.SourceFile, '') <> '' GROUP BY h.collection
),
base AS (
    SELECT h.collection, h.host_name, h.mft_source, h.usn_source,
           e.extension, e.basis AS extension_basis, e.own_ext, e.others_detail,
           t.usn_files, t.mft_files, t.usn_first, t.usn_last, t.usn_peak, t.mft_first, t.mft_last, t.mft_peak,
           t.sample_old, t.sample_new, t.renames,
           j.journal_start,
           n.note_name, n.basis AS note_basis, n.size AS note_size, n.name_key AS note_key,
           ns.folders AS note_folders, ns.first_created AS note_first, ns.last_created AS note_last,
           ns.first_folder AS note_first_folder, ns.first_name AS note_first_name,
           hi.own_note, mr.source_file AS mft_source_file
    FROM rw_host h
    JOIN rw_extension e USING (collection)
    JOIN rw_hints hi USING (collection)
    LEFT JOIN rw_times t USING (collection)
    LEFT JOIN rw_usn_start j USING (collection)
    LEFT JOIN rw_note n USING (collection)
    LEFT JOIN note_stats ns USING (collection)
    LEFT JOIN mft_root mr USING (collection)
),
timed AS (
    SELECT b.*,
           -- From the journal; widened back to the MFT when it holds many more than it renamed.
           b.extension <> '' AND b.usn_first IS NOT NULL AND b.mft_files > b.usn_files * 1.2 + 10 AS mft_holds_more,
           b.extension <> '' AND b.usn_first IS NOT NULL AND b.journal_start IS NOT NULL
               AND b.usn_first - b.journal_start < INTERVAL 10 MINUTES AS journal_wrapped
    FROM base b
),
spans AS (
    SELECT t.*,
           CASE WHEN t.extension = '' THEN NULL
                WHEN t.usn_first IS NOT NULL THEN
                    CASE WHEN t.mft_holds_more AND t.mft_first < t.usn_first THEN t.mft_first ELSE t.usn_first END
                ELSE t.mft_first END AS ext_start,
           CASE WHEN t.extension = '' THEN NULL WHEN t.usn_first IS NOT NULL THEN t.usn_last ELSE t.mft_last END AS ext_finish,
           CASE WHEN t.extension = '' THEN ''
                WHEN t.usn_first IS NOT NULL THEN CASE WHEN t.mft_holds_more THEN 'USN and MFT' ELSE 'USN' END
                WHEN t.mft_first IS NOT NULL THEN 'MFT' ELSE '' END AS ext_source,
           CASE WHEN t.extension = '' THEN NULL
                WHEN t.usn_first IS NOT NULL THEN t.usn_peak ELSE t.mft_peak END AS peak,
           CASE WHEN t.extension = '' THEN 0 ELSE greatest(t.usn_files, t.mft_files) END AS files,
           t.extension <> '' AND (t.journal_wrapped OR t.mft_holds_more OR (t.usn_first IS NULL AND t.mft_first IS NOT NULL))
               AS ext_earliest
    FROM timed t
),
dated AS (
    SELECT w.*,
           w.ext_start IS NULL AND w.note_name <> '' AND w.note_first IS NOT NULL AS note_dates,
           coalesce(w.ext_start, CASE WHEN w.note_name <> '' THEN w.note_first END) AS start_utc,
           CASE WHEN w.ext_start IS NOT NULL THEN w.ext_finish WHEN w.note_name <> '' THEN w.note_last END AS finish_utc,
           CASE WHEN w.ext_start IS NOT NULL THEN w.ext_source
                WHEN w.note_name <> '' AND w.note_first IS NOT NULL THEN 'MFT' ELSE w.ext_source END AS source_text,
           w.ext_earliest OR (w.ext_start IS NULL AND w.note_name <> '' AND w.note_first IS NOT NULL) AS earliest,
           w.extension <> '' OR coalesce(w.note_name, '') <> '' AS anything
    FROM spans w
)
SELECT d.collection, d.host_name,
       CASE WHEN d.anything THEN 'Found' ELSE 'None found' END AS status,
       d.extension, d.extension_basis,
       coalesce(d.note_name, '') AS note_name, coalesce(d.note_basis, '') AS note_basis,
       d.note_size, coalesce(d.note_folders, 0) AS note_folders,
       CASE WHEN d.anything THEN d.start_utc END AS start_utc,
       d.anything AND d.earliest AS earliest,
       CASE WHEN d.anything THEN d.finish_utc END AS finish_utc,
       d.files,
       CASE WHEN d.anything AND d.start_utc IS NOT NULL AND d.finish_utc IS NOT NULL AND d.files > 0
            THEN round_even(d.files / greatest(1.0, epoch(d.finish_utc - d.start_utc) / 60.0), 1) END AS rate,
       d.peak,
       CASE WHEN d.anything THEN d.source_text ELSE '' END AS source,
       concat_ws('; ',
           d.others_detail,
           CASE WHEN d.journal_wrapped THEN 'the USN journal starts at ' || rw_fmt(d.journal_start)
                || ' UTC, just before the first rename: it may have wrapped during encryption' END,
           CASE WHEN d.mft_holds_more THEN 'the MFT holds ' || rw_n0(d.mft_files) || ' files with ' || d.extension
                || ' but the journal renamed ' || rw_n0(d.usn_files) || ': the rest are older than the journal' END,
           CASE WHEN d.extension <> '' AND d.usn_first IS NULL AND d.mft_first IS NOT NULL THEN
                CASE WHEN d.usn_source IS NULL THEN 'no USN journal output, so the times are the files'' last MFT record changes'
                     ELSE 'no renames to it in the USN journal, so the times are the files'' last MFT record changes' END END,
           CASE WHEN d.extension <> '' AND d.renames > 0 THEN 'e.g. ' || d.sample_old || ' renamed to ' || d.sample_new END,
           CASE WHEN d.extension = '' AND d.own_ext = '' THEN 'no extension, as set in Ransomware-Overrides.csv' END,
           CASE WHEN d.note_dates THEN 'no extension found, so the times are when the note''s copies were created' END,
           CASE WHEN d.own_note = '' THEN 'no ransom note, as set in Ransomware-Overrides.csv' END,
           CASE WHEN d.mft_source IS NULL THEN 'no MFT output (FileSystem\MFTECmd_MFT.csv), so no note could be looked for - run MFTECmd_MFT' END,
           CASE WHEN d.usn_source IS NULL AND d.extension <> '' AND d.source_text <> 'MFT' THEN 'no USN journal output' END
       ) AS detail,
       d.note_first_folder, d.note_first_name, d.mft_source_file, d.mft_source, d.usn_source
FROM dated d;

-- --- each host's row, as RansomwareSummary.csv has it ----------------------------------------------
-- A view, so the note copies the lake build saves (ransomware_note_copies) show in it once made.
-- A host with no MFTECmd output is not checked; one whose output did not load is failed, as the
-- C# step fails a file it cannot read.
CREATE OR REPLACE TEMP MACRO rw_path_combine(folder, name) AS
    CASE WHEN folder = '' THEN name WHEN ends_with(folder, '\') OR ends_with(folder, '/') THEN folder || name
         ELSE folder || '\' || name END;

CREATE OR REPLACE TEMP VIEW rw_host_row AS
WITH r AS (
    SELECT v.*, h.mft_status, h.mft_reason, h.usn_status, h.usn_reason, c.attempted, c.note_sha256, c.note_copy,
           CASE WHEN h.mft_source IS NULL AND h.usn_source IS NULL THEN 'Not checked'
                WHEN coalesce(h.mft_status, 'loaded') <> 'loaded' OR coalesce(h.usn_status, 'loaded') <> 'loaded' THEN 'Failed'
                ELSE v.status END AS final_status
    FROM rw_verdict v
    JOIN rw_host h USING (collection)
    LEFT JOIN ransomware_note_copies c USING (collection)
),
checked AS (
    SELECT r.*,
           r.final_status IN ('Found', 'None found') AS ok,
           concat_ws('; ', nullif(r.detail, ''),
               CASE WHEN r.attempted AND coalesce(r.note_copy, '') = '' THEN
                   'the note is not in the collection'
                   || CASE WHEN r.note_first_name IS NOT NULL
                           THEN ': pull a copy from ' || rw_path_combine(r.note_first_folder, r.note_first_name) ELSE '' END
                   || ' (every copy is listed in RansomwareEvidence.csv)' END) AS full_detail
    FROM r
)
SELECT collection AS "Collection",
       host_name AS "Host",
       final_status AS "Status",
       CASE WHEN ok THEN extension ELSE '' END AS "Extension",
       CASE WHEN ok THEN extension_basis ELSE '' END AS "ExtensionBasis",
       CASE WHEN ok THEN note_name ELSE '' END AS "NoteName",
       CASE WHEN ok THEN note_basis ELSE '' END AS "NoteBasis",
       CASE WHEN ok THEN coalesce(note_size::VARCHAR, '') ELSE '' END AS "NoteSize",
       CASE WHEN ok THEN coalesce(note_sha256, '') ELSE '' END AS "NoteSha256",
       CASE WHEN ok THEN coalesce(note_copy, '') ELSE '' END AS "NoteCopy",
       CASE WHEN ok AND note_folders > 0 THEN note_folders::VARCHAR ELSE '' END AS "NoteFolders",
       CASE WHEN ok THEN coalesce(rw_fmt(start_utc), '') ELSE '' END AS "StartUtc",
       CASE WHEN NOT ok OR start_utc IS NULL THEN '' WHEN earliest THEN 'True' ELSE 'False' END AS "StartIsEarliestSeen",
       CASE WHEN ok THEN coalesce(rw_fmt(finish_utc), '') ELSE '' END AS "FinishUtc",
       CASE WHEN ok AND files > 0 THEN files::VARCHAR ELSE '' END AS "FilesAffected",
       CASE WHEN NOT ok OR rate IS NULL THEN ''
            WHEN rate = trunc(rate) THEN rate::BIGINT::VARCHAR ELSE rate::VARCHAR END AS "RatePerMinute",
       CASE WHEN ok THEN coalesce(peak::VARCHAR, '') ELSE '' END AS "PeakPerMinute",
       CASE WHEN ok THEN source ELSE '' END AS "Source",
       '' AS "Differences",
       CASE final_status
            WHEN 'Not checked' THEN 'no MFTECmd output (FileSystem\MFTECmd_MFT.csv or FileSystem\MFTECmd_USNJournal.csv) - run MFTECmd_MFT and MFTECmd_USNJournal'
            WHEN 'Failed' THEN 'could not check for ransomware: '
                 || concat_ws('; ',
                        CASE WHEN coalesce(mft_status, 'loaded') <> 'loaded' THEN 'MFT output ' || mft_status || coalesce(': ' || mft_reason, '') END,
                        CASE WHEN coalesce(usn_status, 'loaded') <> 'loaded' THEN 'USN journal output ' || usn_status || coalesce(': ' || usn_reason, '') END)
            ELSE full_detail END AS "Detail",
       CASE WHEN ok THEN p.parameters ELSE '' END AS "Parameters",
       -- For the lake build's copy of the note; not in ArtefactForge's files.
       note_first_folder AS "NoteFirstFolder",
       note_first_name AS "NoteFirstName",
       mft_source_file AS "MftSourceFile",
       upper(collection) AS "SortKey"
FROM checked
JOIN rw_parameters p USING (collection);
