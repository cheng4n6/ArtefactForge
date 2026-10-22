- EvtxECmd shares the event logs between four processes and joins their output into the same
  EvtxECmd_EventLogs.csv, so a large set of logs is parsed about three times faster. The rows are
  the same as before; only their order differs.
- A Parts option on EvtxECmd sets how many processes (auto, 1, 2, 4 or 8). It runs as one with
  VSS, on a live system, for under 50 MB of logs, or when the logs are not on the case folder's
  volume, and the manifest says how it ran.
