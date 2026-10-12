- New **RDP trace** tab: pick a receiving host and a time (with an optional source IP, account
  and search window), choose one of the RDP sessions it lists, and ArtefactForge follows it back
  host by host until the address is outside the case. Each hop is Confirmed (the source host has
  a client event for the connection), Inferred (the address maps to the host but nothing there
  records connecting), Collect next (an internal host not in the case) or End of chain (an
  external or loopback address). Flags cover DHCP reuse, an address and client name that point
  to different machines (VPN, NAT or a jump host), loopback (tunnelled RDP), log gaps and cleared
  logs, clock differences between hosts, other candidate sessions and account changes. The
  one-line result says how many hops and where it ends; the trace is saved as
  `RdpTrace_<host>_<time>.csv` in the case folder and never overwritten, and saved traces are
  marked when a host they read has been reprocessed or a host has been added. The end IP and the
  accounts used can be added to the IOC list in one click, and an IP or account on the IOC list
  can start a trace (right-click, Trace RDP from this).
- Each Windows host now gets `RemoteAccess\RemoteAccess.csv` after a run: the RDP events from
  its EvtxECmd output (Security 4624 type 10, 4778, 4779, 4634; RemoteConnectionManager 1149;
  LocalSessionManager 21, 23, 24, 25; RdpCoreTS 131; RDPClient 1024 and 1102) plus the Terminal
  Server Client registry keys, mstsc.exe in Prefetch and Amcache, and its jump list.
  `RemoteAccessSources.csv` beside it shows where each log starts and ends and when it was
  cleared. Only a host whose output changed is rebuilt; cases processed earlier build the file
  the first time they are traced.
- `ArtefactForgeCli rdp <case folder>` lists the RDP sessions (filter with `--host`, `--at`,
  `--window`, `--ip`, `--account`) and `--trace <n>` traces one and saves it.
