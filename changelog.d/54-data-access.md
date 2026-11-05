- **Data access:** a new Data access page under Analysis lists every account on every host
  (`UserList.csv`, with SIDs from ProfileList and the SAM) and lets you tick the compromised ones
  or list them by username or SID in `CompromisedUsers.csv`. Build report writes `DataAccess.csv`:
  the files and folders those accounts opened or browsed, with date and time (UTC), system, user,
  path and activity, from LNK files, jump lists, ShellBags, RecentDocs, OpenSavePidlMRU, Office
  File MRU and file share events (5140/5145). Rows with no time are left out. It works on cases
  processed before this release without running anything again, and is rebuilt after each run.
  `ArtefactForgeCli data-access <case> [--add <user or SID>]` does the same from the command line.
