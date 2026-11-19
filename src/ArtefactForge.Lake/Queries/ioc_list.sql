-- title: IOC sweep: the IOCs looked for
-- category: ioc
-- requires: ioc_prepare
-- description: The rows of the case's IOCs.csv that the sweep looks for (a type it knows and a
--   value), in the file's order, with the forms each is matched in.
SELECT e.type_label AS "IocType", e.value AS "Ioc", e.ioc_type AS "Kind",
       (SELECT string_agg(v.form, ' | ' ORDER BY v.form) FROM ioc_variant v WHERE v.input_row = e.input_row) AS "Forms"
FROM ioc_entry e
ORDER BY e.input_row;
