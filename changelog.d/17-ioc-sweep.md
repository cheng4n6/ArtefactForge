- A case can keep a list of IOCs, and ArtefactForge searches every host's parsed output for
  them. The list is `IOCs.csv` in the case folder (Type, Value, Note, Found on), edited from the
  new IOCs tab or with the new `ioc` command, and can be imported from another case's list or a
  plain list of values. Adding an IOC searches for that IOC alone across every host; processing
  a host again rebuilds that host's hits against the whole list and leaves the other hosts'
  hits as they were. Hits go to `IocHits.csv` in the case folder, with the host, module, time,
  output file and matching line, and the IOCs tab shows how many hits and hosts each IOC has.
  File names match on the name in any folder, hashes match in any hash column, and IPs, domains
  and accounts match anywhere in a line as a whole value. ArtefactForge never rewrites
  `IOCs.csv` on its own: only adding, removing or importing IOCs changes it, and an edit made in
  Excel in the meantime is kept.
