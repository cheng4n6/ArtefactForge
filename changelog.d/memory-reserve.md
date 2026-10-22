- Added: a Keep free setting (1 GB by default, 0 turns it off, --keep-free on the command line).
  No new module starts while free memory is under it, unless nothing else is running, so a PC
  that is short of memory works through the batch instead of paging.
- Changed: the memory-heavy modules also leave that much free memory for everything else.
