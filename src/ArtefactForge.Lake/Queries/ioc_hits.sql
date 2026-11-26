-- title: IOC sweep: every hit of the case's IOCs in the hosts' output
-- category: ioc
-- severity: high
-- requires: ioc_prepare
-- description: The case's IocHits.csv: one row per IOC found in a row of a host's output, with
--   the module that wrote the file, the row's first time, the file, the row's line in it, and the
--   row written back from its cells (cut at Excel's 32,000 characters). The match itself is made
--   by af-lake ioc and the lake build, one IOC form at a time (ioc_row_matches, so each pattern
--   is compiled once); run alone, before that, this lists nothing.
WITH hits AS (
    SELECT m.source_id, m.row_no, m.input_row, any_value(c.host) AS host, any_value(c.names) AS names,
           any_value(c.cells) AS cells, any_value(c.line) AS line
    FROM (SELECT DISTINCT * FROM ioc_matched) m
    JOIN ioc_candidate c ON c.source_id = m.source_id AND c.row_no = m.row_no AND c.input_row = m.input_row
    GROUP BY m.source_id, m.row_no, m.input_row
),
-- Line breaks inside cells, for every row of the files with a hit: each pushes the rows after it down.
breaks AS (
    SELECT source_id, row_no,
           coalesce(sum(ioc_breaks(cells)) OVER (PARTITION BY source_id ORDER BY row_no
                                                ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING), 0) AS before
    FROM ioc_lake_rows
    WHERE source_id IN (SELECT DISTINCT source_id FROM ioc_matched)
),
placed AS (
    SELECT h.*, e.type_label, e.value, s.path,
           h.host || '\' || replace(s.path, '/', '\') AS output_file,
           h.row_no + 1 + b.before AS line_number,
           -- The first time or date column with a value, in column order (CsvHeader.TimeOf).
           coalesce(list_filter(list_transform(range(1, len(h.names) + 1),
                                               i -> CASE WHEN ioc_time_column(h.names[i]) THEN ioc_trim(h.cells[i]) END),
                                t -> t IS NOT NULL AND t <> '')[1], '') AS time
    FROM hits h
    JOIN ioc_entry e ON e.input_row = h.input_row
    JOIN sources s ON s.source_id = h.source_id
    JOIN breaks b ON b.source_id = h.source_id AND b.row_no = h.row_no
)
SELECT p.type_label AS "IocType", p.value AS "Ioc", p.host AS "Host",
       coalesce(m.module, CASE WHEN contains(p.path, '/') THEN split_part(p.path, '/', 1) ELSE '' END) AS "Module",
       p.time AS "Time", p.output_file AS "OutputFile", CAST(p.line_number AS VARCHAR) AS "LineNumber",
       CASE WHEN length(p.line) <= 32000 THEN p.line
            ELSE substr(p.line, 1, 32000) || ' [cut: ' || format('{:,}', length(p.line)) || ' characters in the output file]' END
           AS "MatchingLine"
FROM placed p
LEFT JOIN ioc_modules m ON lower(m.output_file) = lower(p.output_file)
ORDER BY upper(p.value), upper(p.host), upper(p.output_file), p.line_number, p.input_row;
