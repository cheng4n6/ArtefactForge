- Each tool's peak memory use is recorded in the run manifest (a PeakMemoryMB column in
  manifest.csv, PeakMemoryBytes in manifest.json), and the end of a run names the three tools
  that used the most. It is measured on the PC that ran the case, so it reflects that PC's cores
  and RAM. Builtins and processes a tool starts are not counted.
