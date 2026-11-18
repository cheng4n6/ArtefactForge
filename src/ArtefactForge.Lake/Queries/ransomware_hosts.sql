-- title: Ransomware: one row per host
-- category: ransomware
-- severity: critical
-- requires: ransomware_prepare
-- description: Each host's ransomware verdict from its MFTECmd $MFT and USN journal output: the
--   extension added to encrypted files, the ransom note, when encryption started and finished,
--   how many files and how fast. The columns of ArtefactForge's RansomwareSummary.csv, plus
--   Parameters (what Ransomware-Overrides.csv said about the host), and the note's first copy and
--   the $MFT path, which the lake build uses to save a copy of the note.
SELECT * EXCLUDE ("SortKey")
FROM rw_host_row
ORDER BY "SortKey", "Collection";
