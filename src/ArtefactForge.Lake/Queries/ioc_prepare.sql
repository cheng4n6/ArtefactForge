-- title: IOC sweep: working tables for the IOC sweep queries
-- category: ioc
-- type: setup
-- description: Reads the analyst's IOCs.csv and finds each IOC in the rows of every host's
--   output, with the rules of ArtefactForge's IOC sweep: file names, accounts, IPs and domains as
--   whole values anywhere in a row, paths with either separator, doubled backslashes or without
--   the drive, and hashes in hash columns only (Amcache's 0000-prefixed FileId too). A row is the
--   lake's parsed cells written back as one CSV line, so the line can differ from the file's in
--   its quoting, though not in what it matches.
-- input: ioc_list = IOCs.csv (Type, Value)
-- allrows: ioc_lake_rows

-- How IocMatcher (ArtefactForge.Core) reads each rule, and why, is on that class; this is the same
-- test in SQL. Its Bounded test (the value, with no character of the value's kind on either side)
-- is a regular expression here: the characters either side are part of the match, which does
-- not change whether there is one.

-- .NET's Trim(): Unicode white space.
CREATE OR REPLACE TEMP MACRO ioc_trim(x) AS
    regexp_replace(coalesce(x, ''), '^[\t\n\v\f\r\x{85}\p{Z}]+|[\t\n\v\f\r\x{85}\p{Z}]+$', '', 'g');
-- A value as a regular expression that matches it literally.
CREATE OR REPLACE TEMP MACRO ioc_literal(v) AS regexp_replace(v, '([\\.^$|?*+()\[\]{}])', '\\\1', 'g');
-- The characters that continue a file or account name (.NET's IsLetterOrDigit, and _ - . $).
CREATE OR REPLACE TEMP MACRO ioc_name_class() AS '\pL\p{Nd}_.$-';
-- IocList.ParseType: the label's letters and digits, in lower case.
CREATE OR REPLACE TEMP MACRO ioc_type(label) AS
    CASE lower(regexp_replace(coalesce(label, ''), '[^\pL\p{Nd}]', '', 'g'))
        WHEN 'filename' THEN 'FileName' WHEN 'file' THEN 'FileName'
        WHEN 'path' THEN 'Path' WHEN 'filepath' THEN 'Path' WHEN 'fullpath' THEN 'Path' WHEN 'folder' THEN 'Path'
        WHEN 'hash' THEN 'Hash' WHEN 'md5' THEN 'Hash' WHEN 'sha1' THEN 'Hash' WHEN 'sha256' THEN 'Hash'
        WHEN 'sha512' THEN 'Hash' WHEN 'filehash' THEN 'Hash'
        WHEN 'ip' THEN 'IP' WHEN 'ipaddress' THEN 'IP' WHEN 'ipv4' THEN 'IP' WHEN 'ipv6' THEN 'IP'
        WHEN 'domain' THEN 'Domain' WHEN 'domainname' THEN 'Domain' WHEN 'hostname' THEN 'Domain' WHEN 'fqdn' THEN 'Domain'
        WHEN 'account' THEN 'Account' WHEN 'user' THEN 'Account' WHEN 'username' THEN 'Account'
        WHEN 'useraccount' THEN 'Account' WHEN 'sid' THEN 'Account' WHEN 'email' THEN 'Account'
    END;
-- CsvHeader: a column whose name says it holds a hash (SHA1, MD5, Hashes; not Shadow or Shared),
-- or a time or date (not a time zone).
CREATE OR REPLACE TEMP MACRO ioc_hash_column(n) AS
    contains(lower(n), 'hash') OR contains(lower(n), 'md5') OR lower(n) = 'sha'
    OR regexp_matches(lower(n), 'sha[0-9-]');
CREATE OR REPLACE TEMP MACRO ioc_time_column(n) AS
    (contains(lower(n), 'time') OR contains(lower(n), 'date')) AND NOT contains(lower(n), 'zone');
-- A cell as CSV writes it when it must: quoted when it holds a comma, a quote or a line break.
CREATE OR REPLACE TEMP MACRO ioc_csv_cell(c) AS
    CASE WHEN regexp_matches(coalesce(c, ''), '[,"\r\n]') THEN '"' || replace(c, '"', '""') || '"' ELSE coalesce(c, '') END;

-- --- the list ---------------------------------------------------------------------------------
-- In the file's order, which is the order a row's hits are listed in. A row with a type the sweep
-- does not know, or no value, is kept on the list but not looked for.
CREATE OR REPLACE TEMP TABLE ioc_entry AS
SELECT input_row, coalesce("Type", '') AS type_label, coalesce("Value", '') AS value,
       ioc_type("Type") AS ioc_type, ioc_trim("Value") AS v
FROM ioc_list
WHERE ioc_type("Type") IS NOT NULL AND ioc_trim("Value") <> '';

-- The forms each IOC is looked for in (IocMatcher.Variants), each as a pattern with its type's
-- boundaries (StartsClean, EndsClean).
CREATE OR REPLACE TEMP TABLE ioc_variant AS
WITH forms AS (
    SELECT e.*, unnest(CASE
        WHEN e.ioc_type = 'Path' THEN
            list_distinct(flatten(list_transform(
                CASE WHEN length(replace(e.v, '/', '\')) > 2 AND substr(replace(e.v, '/', '\'), 2, 2) = ':\'
                     THEN [replace(e.v, '/', '\'), substr(replace(e.v, '/', '\'), 3)]
                     ELSE [replace(e.v, '/', '\')] END,
                f -> [f, replace(f, '\', '/'), replace(f, '\', '\\')])))
        WHEN e.ioc_type = 'Account' AND contains(e.v, '\') THEN [e.v, replace(e.v, '\', '\\')]
        ELSE [e.v] END) AS form
    FROM ioc_entry e
)
SELECT input_row, type_label, value, ioc_type, v, form, lower(form) AS lower_form,
       '(?i)' || CASE ioc_type
           WHEN 'Path' THEN ioc_literal(form)
               || CASE WHEN ends_with(form, '\') OR ends_with(form, '/') THEN '' ELSE '($|[^' || ioc_name_class() || '])' END
           WHEN 'IP' THEN '(^|[^' || CASE WHEN contains(v, ':') THEN '0-9A-Fa-f:.' ELSE '0-9.' END || '])'
               || ioc_literal(form) || '($|[^' || CASE WHEN contains(v, ':') THEN '0-9A-Fa-f:.' ELSE '0-9.' END || '])'
           WHEN 'Hash' THEN '(^|[^0-9A-Fa-f])' || ioc_literal(form) || '($|[^0-9A-Fa-f])'
           WHEN 'Domain' THEN '(^|[^A-Za-z0-9-])' || ioc_literal(form) || '($|[^A-Za-z0-9.-]|\.($|[^A-Za-z0-9]))'
           ELSE '(^|[^' || ioc_name_class() || '])' || ioc_literal(form) || '($|[^' || ioc_name_class() || '])'
       END AS pattern
FROM forms;

-- The module that wrote each output file, from the case's last run (ArtefactForge fills it from
-- _Logs\manifest.json before the hits are read); a file it does not name is named by its folder.
CREATE TEMP TABLE IF NOT EXISTS ioc_modules (output_file VARCHAR, module VARCHAR);

-- --- the rows -----------------------------------------------------------------------------------
-- Each row as one line, and where its hash and time columns are. A Hash IOC is only looked for in
-- a file with a hash column (CsvHeader.HashColumns); every other type in any row.
CREATE OR REPLACE TEMP TABLE ioc_candidate AS
WITH rows AS (
    SELECT r.host, r.source_id, r.row_no, r.names, r.cells,
           array_to_string(list_transform(r.cells, c -> ioc_csv_cell(c)), ',') AS line
    FROM ioc_lake_rows r
    WHERE EXISTS (SELECT 1 FROM ioc_variant)
)
SELECT r.*, v.input_row, v.type_label, v.value, v.ioc_type, v.v, v.pattern
FROM rows r JOIN ioc_variant v ON contains(lower(r.line), v.lower_form);

CREATE OR REPLACE TEMP TABLE ioc_hit AS
WITH matched AS (
    SELECT DISTINCT c.host, c.source_id, c.row_no, c.names, c.cells, c.line, c.input_row, c.type_label, c.value
    FROM ioc_candidate c
    WHERE (c.ioc_type <> 'Hash' AND regexp_matches(c.line, c.pattern))
       OR (c.ioc_type = 'Hash' AND len(list_filter(range(1, len(c.names) + 1), i ->
               ioc_hash_column(c.names[i])
               AND length(ioc_trim(c.cells[i])) >= length(c.v)
               AND ((length(ioc_trim(c.cells[i])) = length(c.v) + 4 AND starts_with(ioc_trim(c.cells[i]), '0000')
                     AND ends_with(lower(ioc_trim(c.cells[i])), lower(c.v)))
                    OR regexp_matches(ioc_trim(c.cells[i]), c.pattern)))) > 0)
)
SELECT m.*,
       s.path,
       m.host || '\' || replace(s.path, '/', '\') AS output_file,
       -- The first time or date column with a value, in column order (CsvHeader.TimeOf).
       coalesce(list_filter(list_transform(range(1, len(m.names) + 1),
                                           i -> CASE WHEN ioc_time_column(m.names[i]) THEN ioc_trim(m.cells[i]) END),
                            t -> t IS NOT NULL AND t <> '')[1], '') AS time
FROM matched m JOIN sources s ON s.source_id = m.source_id;
