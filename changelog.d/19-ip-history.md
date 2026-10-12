- When a domain controller is processed, ArtefactForge builds a history of which machine had which
  IP address and when, in `IpHistory\IpHistory.csv` for that collection and `IpHistory.csv` at the
  case root, merged across every DC and each host's own addresses. The columns are IpAddress,
  HostName, Account, MacAddress, FirstSeenUtc, LastSeenUtc, Source, EventCount and Collection.
  The main source is the DC's Kerberos events (4768 and 4769, from EvtxECmd), so EvtxECmd has to
  be selected. DHCP server audit logs and the DNS Server audit log are added when the collection
  has them. `IpHistory\IpHistorySources.csv` and the run results show which sources were used,
  the time range each covers, and which were not present. A DC with no Kerberos events is
  marked for review.
- New module `WindowsDhcpServerLog`: the DHCP server's audit logs (`DhcpSrvLog-*.log`,
  `DhcpV6SrvLog-*.log`), about a week of leases with address, host name and MAC. Times are
  converted from the server's local time to UTC using the time zone in its SYSTEM hive.
- `ArtefactForgeCli ip <case folder> <address> --at "yyyy-MM-dd HH:mm:ss"` answers "who had this
  address at this time (UTC)" from the case's IP history, with any other machine seen on the
  same address in that period listed as a conflict.
