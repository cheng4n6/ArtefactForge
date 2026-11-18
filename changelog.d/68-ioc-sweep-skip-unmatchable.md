### Changes

* **IOC sweep:** a sweep that looks only for hashes no longer reads output files that have no hash column, such as the MFT and event log CSVs, where a hash could never match. The sweep's result line says how many files were not read for that reason.
