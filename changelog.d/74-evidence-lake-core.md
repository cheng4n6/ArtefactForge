### Features

* **Evidence lake (preview):** the package now includes af-lake.exe, which loads a case's parser output into one DuckDB file, `_Lake\case.duckdb`, with a cross-host timeline of event logs, Prefetch and the MFT and USN journal, and every other CSV kept in its own table. It reads each host's outputs.json, or recognises raw EZ Tools and KAPE output by file name and header. Run `af-lake build <case folder>`; lake.log lists anything that was not loaded and why. It is not yet started from ArtefactForge itself.
