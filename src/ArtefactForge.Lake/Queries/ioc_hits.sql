-- title: IOC sweep: every hit of the case's IOCs in the hosts' output
-- category: ioc
-- severity: high
-- requires: ioc_prepare
-- description: The case's IocHits.csv: one row per IOC found in a row of a host's output, with
--   the module that wrote the file, the row's first time, the file and the row. LineNumber is the
--   row's line in the file when no cell before it spans lines (row_no + 1, the header being line
--   1), and MatchingLine the row written back from its cells, cut at Excel's 32,000 characters.
SELECT h.type_label AS "IocType", h.value AS "Ioc", h.host AS "Host",
       coalesce(m.module, CASE WHEN contains(h.path, '/') THEN split_part(h.path, '/', 1) ELSE '' END) AS "Module",
       h.time AS "Time", h.output_file AS "OutputFile", CAST(h.row_no + 1 AS VARCHAR) AS "LineNumber",
       CASE WHEN length(h.line) <= 32000 THEN h.line
            ELSE substr(h.line, 1, 32000) || ' [cut: ' || format('{:,}', length(h.line)) || ' characters in the output file]' END
           AS "MatchingLine"
FROM ioc_hit h
LEFT JOIN ioc_modules m ON lower(m.output_file) = lower(h.output_file)
ORDER BY upper(h.value), upper(h.host), upper(h.output_file), h.row_no, h.input_row;
