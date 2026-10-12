- Each case now has an evidence list, `EvidenceList.xlsx` at the case root, with one row per
  collection: hostname, domain, IP addresses, OS version, detected role and serial number, the
  zip or folder it came from and the date it was added. The shaded columns (evidence reference,
  confirmed role, serial number, notes) are yours, as is any column or row you add: what you
  type is kept every time the list is rebuilt. New collections are added as new rows, and a
  collection removed from the case keeps its row, marked Missing.
- The list is rebuilt after every run, and from the results page with "Rebuild evidence list"
  (or `ArtefactForgeCli evidence-list <case folder>`) without running any modules. If the list
  is open in Excel when a run starts you are asked to save and close it; if it is still open
  when the run ends it is left untouched and marked out of date until you rebuild it.
- Linux collections from UAC show the addresses the system was using at collection time (from
  `ip addr`) and the system serial number (from `dmidecode`) in the system summary.
