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
SELECT row_number() OVER (ORDER BY input_row, form) AS variant_id,
       input_row, type_label, value, ioc_type, v, form, lower(form) AS lower_form,
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
-- Rows that contain one of the forms, ignoring case: only these are tested against the form's
-- pattern, as IocMatcher first looks for any value in a record before testing each.
CREATE OR REPLACE TEMP TABLE ioc_candidate AS
WITH rows AS (
    -- A line break inside a cell as the sweep reads it: the file's lines joined with \n.
    SELECT r.host, r.source_id, r.row_no, r.names, r.cells,
           regexp_replace(array_to_string(list_transform(r.cells, c -> ioc_csv_cell(c)), ','), '\r\n|\r', chr(10), 'g') AS line
    FROM ioc_lake_rows r
    WHERE EXISTS (SELECT 1 FROM ioc_variant)
)
SELECT r.*, v.variant_id, v.input_row
FROM rows r JOIN ioc_variant v ON contains(lower(r.line), v.lower_form);

-- Whether a candidate row holds the IOC as a whole value: anywhere in the line, or for a hash in
-- a hash column only (as a whole value, or as Amcache's 0000-prefixed FileId). It is called once
-- per form with that form's pattern written in as text (ArtefactForge's IOC step does this from
-- ioc_variant), so each pattern is compiled once: a pattern read from a column would be compiled
-- again for every row.
CREATE OR REPLACE TEMP MACRO ioc_row_matches(line, names, cells, ioc_type, v, pattern) AS
    CASE WHEN ioc_type <> 'Hash' THEN regexp_matches(line, pattern)
         ELSE len(list_filter(range(1, len(names) + 1), i ->
                  ioc_hash_column(names[i])
                  AND length(ioc_trim(cells[i])) >= length(v)
                  AND ((length(ioc_trim(cells[i])) = length(v) + 4 AND starts_with(ioc_trim(cells[i]), '0000')
                        AND ends_with(lower(ioc_trim(cells[i])), lower(v)))
                       OR regexp_matches(ioc_trim(cells[i]), pattern)))) > 0 END;

-- The rows each IOC was found in, filled one form at a time.
CREATE OR REPLACE TEMP TABLE ioc_matched (source_id INTEGER, row_no BIGINT, input_row BIGINT);

-- A row's line in its file: the header is line 1, and a cell holding line breaks (a quoted
-- multi-line value) pushes every later row down by that many lines, as the C# sweep counts them.
CREATE OR REPLACE TEMP MACRO ioc_breaks(cells) AS
    len(regexp_split_to_array(array_to_string(list_transform(cells, c -> coalesce(c, '')), ''), '\r\n|\r|\n')) - 1;
