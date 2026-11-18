-- title: Ransomware: where each host's ransom note can be read from
-- category: ransomware
-- severity: info
-- requires: ransomware_prepare
-- description: Up to 20 copies of each host's note still in use at the note's size, in MFT order:
--   the folder and name, the $MFT path MFTECmd read (the collection's root is the folder it is
--   in), and the note's content when the MFT holds it (resident, base64). The lake build reads
--   the first copy it can to save the note and its hash.
SELECT c.collection AS "Collection",
       row_number() OVER (PARTITION BY c.collection ORDER BY c.row_no) AS "Copy",
       c.folder AS "Path",
       c.name AS "Name",
       c.size AS "Size",
       coalesce(v.mft_source_file, '') AS "MftSourceFile",
       c.resident AS "ResidentDataBase64"
FROM rw_hit_note c
JOIN rw_verdict v USING (collection)
WHERE c.in_use AND c.size = v.note_size AND v.note_name <> ''
QUALIFY "Copy" <= 20
ORDER BY upper(c.collection), c.collection, "Copy";
