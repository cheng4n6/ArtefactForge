- Faster zip extraction: the zip's SHA-256 is now read alongside the extraction instead of in a
  full pass before it starts, and each entry's CRC-32 check is many times quicker. Folders are
  made once per extraction rather than once per file.
- The IOC sweep starts with the largest output files, so a big MFT or event log CSV no longer
  runs alone at the end of a sweep.
- Tools now run at below normal priority, so the app and the rest of the PC stay responsive
  during a long run. An otherwise idle PC runs them as fast as before.
- The run log and progress tree no longer slow the window down as a large batch goes on, and the
  IOCs tab loads its hit counts without freezing the window.
