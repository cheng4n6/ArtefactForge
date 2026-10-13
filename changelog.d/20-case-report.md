- Each case now has a case report, `CaseReport.html` in the case folder: one page that opens in
  any browser with no internet and no server. It starts with what needs attention (critical and
  high detections, IOC hits, RDP traces that end outside the case, hosts to collect next and
  gaps such as a cleared Security log), then has a section each for the hosts (role, OS,
  addresses, how their last run went, how far back the Security log reaches and detections by
  level), Hayabusa and Chainsaw detections grouped by rule, IOC hits with the matching text
  marked, saved RDP traces drawn as a chain with their hops and flags, and the IP history with
  a "who had this address at this time" lookup. It follows the system's light or dark theme.
- The report is rebuilt after every run, IOC sweep and RDP trace. Nothing in it is typed by
  hand, so rebuilding never loses anything. "Open case report" on the results page (and "Open
  report" on the IOCs and RDP trace tabs) opens it; "Export snapshot" saves a dated copy,
  `CaseReport_<date>_<time>.html`, that is never updated, for sending.
- `ArtefactForgeCli report <case folder>` rebuilds the report, and `--snapshot` saves a dated copy.
