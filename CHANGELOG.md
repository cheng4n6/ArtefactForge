# Changelog

## Unreleased

## 0.3.0 - 2026-10-25

### Features

- **Ransomware:** each Windows host is checked for ransomware from its MFT and USN journal
  output: the extension added to encrypted files, the ransom note (a copy is saved in the case
  when the collection holds one, with its hash), and when encryption started and finished, with
  files per minute. When the journal does not reach back far enough the start is marked
  "earliest seen". `Ransomware.csv` in the case folder has one row per host and flags hosts that
  differ from the rest. A new Ransomware page under Analysis shows one line per host, the
  Overview has a Ransomware row, and the case report has a section with each host's encryption
  window on one time line. `ArtefactForgeCli ransomware <case>` does the same from the command line.
- **Ransomware:** confirm or correct a host's extension or note in `Ransomware-Overrides.csv`
  (Edit overrides creates it). ArtefactForge never changes that file. A confirmed extension or
  note is looked for on every other host in the case, and only hosts whose output or overrides
  changed are checked again.
- With the window a quarter wider than its default size or more (1475 pixels, or maximised),
  the Setup page uses the extra width. In the List view each category row shows a chip per
  module that switches it on or off without opening the category (off modules are struck
  through, heavy ones carry an amber dot), with Runs on and a Heavy badge for the category. In
  the Rail view the chosen category's modules are cards with their options edited in place:
  options changed from their defaults are highlighted with the default and a Reset link, the
  rail marks categories with changed options, and above the list a count of changed options sits
  beside Reset all options and an Only show changed filter. The Profile box reads "(current
  selection, modified)" while options are changed. The default window size keeps the layout it
  had.
- Each tool's peak memory use is recorded in the run manifest (a PeakMemoryMB column in
  manifest.csv, PeakMemoryBytes in manifest.json), and the end of a run names the three tools
  that used the most. It is measured on the PC that ran the case, so it reflects that PC's cores
  and RAM. Builtins and processes a tool starts are not counted.
- EvtxECmd shares the event logs between four processes and joins their output into the same
  EvtxECmd_EventLogs.csv, so a large set of logs is parsed faster on a multi-core PC. The rows are
  the same as before; only their order differs.
- A Parts option on EvtxECmd sets how many processes (auto, 1, 2, 4 or 8). It runs as one with
  VSS, on a live system, for under 50 MB of logs, or when the logs are not on the case folder's
  volume, and the manifest says how it ran.
- a Keep free setting (1 GB by default, 0 turns it off, --keep-free on the command line).
  No new module starts while free memory is under it, unless nothing else is running, so a PC
  that is short of memory works through the batch instead of paging.

### Changes

- memory-heavy modules no longer always run one at a time. They share the memory free
  when the run starts, each counted at its measured peak, so MFTECmd, Hayabusa and Chainsaw run
  side by side on a typical workstation while two of Chainsaw's SRUM analysis never do. The
  budget used is in the manifest.
- the memory-heavy module that took longest when the case last ran starts first, and
  Chainsaw now starts before Hayabusa on a first run.
- MFTECmd_MFT is now memory-heavy (about twice the $MFT in memory, 2.4 GB for a 1.2 GB
  $MFT) and ChainsawGaps no longer is (30 MB), from measurements on a 2 GB collection.
- the memory-heavy modules also leave that much free memory for everything else.
- Faster zip extraction: the zip's SHA-256 is now read alongside the extraction instead of in a
  full pass before it starts, and each entry's CRC-32 check is many times quicker. Folders are
  made once per extraction rather than once per file.
- The IOC sweep starts with the largest output files, so a big MFT or event log CSV no longer
  runs alone at the end of a sweep.
- Tools now run at below normal priority, so the app and the rest of the PC stay responsive
  during a long run. An otherwise idle PC runs them as fast as before.
- The run log and progress tree no longer slow the window down as a large batch goes on, and the
  IOCs tab loads its hit counts without freezing the window.
- Zips are extracted a few files at a time on a multi-core PC, largest first, so unpacking a
  large collection takes less time. Tar files and folders are still copied one file at a time.
- The RDP trace and IP history read EvtxECmd's CSV about a third faster: the file is scanned in
  blocks, and the large Payload column is read only for the events they use.
- In a run over several hosts, each host's IP history, RDP trace, ransomware check and IOC sweep
  start as soon as that host's modules finish, beside the other hosts' modules, instead of waiting
  for the whole run.

### Bug fixes

- the app now puts Workers, Heavy IO, Keep free and Zips at once in range when a run
  starts, as it already did for the saved settings. A box that is not a number, or a value that
  had to change, stops the run with a message and the box shows the value that will be used.
- `--workers`, `--heavy`, `--zips-at-once` and `--keep-free` stop with an error when the
  value is not a number, instead of quietly using the default, and a value out of range is
  brought into range with a note saying so.

## 0.2.1 - 2026-10-21

### Bug fixes

* **Registry:** a dirty hive collected without its .LOG1/.LOG2 files is read as last written to
  disk instead of being skipped in silence, and the module is flagged for review, as recent
  entries may be missing. Re-run Amcache, ShimCache, ShellBags and RECmd on affected collections.
* **Updates:** the release notes shown by Check for updates fill the width of the panel.

## 0.2.0 - 2026-10-20

- The tools you use on a case after it is processed are grouped on one **Analysis**
  tab, so the main tabs are Setup, Run, Results, Analysis, Tools and Settings. A bar at the top
  shows the case, its host count and when its report was last updated, with Open case folder,
  Export snapshot and Open report. Below it are pages for IOCs, RDP trace, IP history and the
  evidence list, and an Overview page with a one-line status for each and a button to open it.
- Each case now has a case report, `CaseReport.html` in the case folder: one page that opens in
  any browser with no internet and no server. It starts with what needs attention (critical and
  high detections, IOC hits, RDP traces that end outside the case, hosts to collect next and
  gaps such as a cleared Security log), then has a section each for the hosts (role, OS,
  addresses, how their last run went, how far back the Security log reaches and detections by
  level), Hayabusa and Chainsaw detections grouped by rule, IOC hits with the matching text
  marked, saved RDP traces drawn as a chain with their hops and flags, and the IP history with
  a "who had this address at this time" lookup. It follows the system's light or dark theme.
- The report is rebuilt after every run, IOC sweep and RDP trace. Nothing in it is typed by
  hand, so rebuilding never loses anything. "Open report" at the top of the Analysis tab opens
  it; "Export snapshot" beside it saves a dated copy,
  `CaseReport_<date>_<time>.html`, that is never updated, for sending.
- `ArtefactForgeCli report <case folder>` rebuilds the report, and `--snapshot` saves a dated copy.
- A host collected more than once into the case (two folders whose system summaries give the
  same hostname) counts as one host in the report header, and its detections are counted once:
  each rule takes the higher of the collections' counts. The host is marked "Collected N times"
  in the Hosts section and raised under "Needs attention".
- Each case now has an evidence list, `EvidenceList.xlsx` at the case root, with one row per
  collection: hostname, domain, IP addresses, OS version, detected role and serial number, the
  zip or folder it came from and the date it was added. The shaded columns (evidence reference,
  confirmed role, serial number, notes) are yours, as is any column or row you add: what you
  type is kept every time the list is rebuilt. New collections are added as new rows, and a
  collection removed from the case keeps its row, marked Missing.
- The list is rebuilt after every run, and from Analysis > Evidence list with "Rebuild evidence
  list" (or `ArtefactForgeCli evidence-list <case folder>`) without running any modules. If the
  list is open in Excel when a run starts you are asked to save and close it; if it is still open
  when the run ends it is left untouched and marked out of date until you rebuild it.
- Linux collections from UAC show the addresses the system was using at collection time (from
  `ip addr`) and the system serial number (from `dmidecode`) in the system summary.
- A case can keep a list of IOCs, and ArtefactForge searches every host's parsed output for them.
  The list is `IOCs.csv` in the case folder (Type, Value, Note, Found on), edited from the IOCs
  page of the Analysis tab or with the new `ioc` command, and can be imported from another case's
  list or a plain list of values. Adding an IOC searches for that IOC alone across every host;
  processing a host again rebuilds that host's hits against the whole list and leaves the other
  hosts' hits as they were. Hits go to `IocHits.csv` in the case folder, with the host, module,
  time, output file and matching line, and the IOCs page shows how many hits and hosts each IOC
  has. File names match on the name in any folder, hashes match in any hash column, and IPs,
  domains and accounts match anywhere in a line as a whole value. ArtefactForge never rewrites
  `IOCs.csv` on its own: only adding, removing or importing IOCs changes it, and an edit made in
  Excel in the meantime is kept.
- New **RDP trace** page on the Analysis tab: pick a receiving host and a time (with an optional
  source IP, account and search window), choose one of the RDP sessions it lists, and
  ArtefactForge follows it back host by host until the address is outside the case. Each hop is
  Confirmed (the source host has a client event for the connection), Inferred (the address maps to
  the host but nothing there records connecting), Collect next (an internal host not in the case)
  or End of chain (an external or loopback address). Flags cover DHCP reuse, an address and client
  name that point to different machines (VPN, NAT or a jump host), loopback (tunnelled RDP), log
  gaps and cleared logs, clock differences between hosts, other candidate sessions and account
  changes. The one-line result says how many hops and where it ends; the trace is saved as
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
- The new IP history page shows what the case's `IpHistory.csv` holds and answers "which machine
  had this address at this time" for one address, warning when two machines held it in that span.
- Checking for Hayabusa and Chainsaw updates shows the installed version. It said "installed
  version unknown" for tools copied into `Tools\`, because the version came only from a
  `VERSIONS.txt` that the package does not include. The version is now read from the program
  itself. The tools list and the run manifest show Chainsaw's version too, which was blank.
- Collection zips extract when the output folder is on a network share (`\\server\share\...`).
  The free-space check before extracting accepted only a drive letter, so every zip failed with
  an error that the path was not a root directory such as `C:\`.

## 0.1.1 - 2026-10-12

- Cleanup of extracted zips no longer reports "could not delete" for a zip it did delete. When
  two zips finished at the same moment, both tried to remove the shared `_Extracted` folder and
  the second was reported as a failed cleanup. The folder is now removed once every zip is done.
- `tools` checks the tool roots given with `--tools` (and in `--config`), the same ones `run` and
  `plan` search. It listed tools kept elsewhere as missing although a run found and used them.

## 0.1.0 - 2026-10-11

First public release, 0.1.0, a beta published as a GitHub pre-release. ArtefactForge was developed
privately as ArtifactForge up to 1.6.0; this repository starts its history and its version numbers
afresh. The 0.x betas are for feedback and bug fixing ahead of a full 1.0.0 release.

- Renamed to ArtefactForge throughout: executables, projects, namespaces and documentation.
- MIT licence.
- The README is a short landing page and is what ships in the package. The full manual moves to
  cheng4n6.com.
- Per-user output sits in a folder per user inside each category - `Registry\alice\`,
  `LNKFiles\alice\`, `JumpLists\alice\`, `Timeline\alice\`, `UserFiles\alice\` - so one profile's
  files are together.
- ShellBags from a collection are parsed per user, into `ShellBags\<user>\`, instead of one
  combined file.
- SRUM from a Velociraptor collection is parsed. The database is copied while Windows has it
  open, and SrumECmd could not open the copy, so the module came back with no output. The copy
  is now recovered from its transaction logs first, as Windows would.
- ShellBags on a live system are parsed per user too, into `ShellBags\<user>\`, and cover every
  profile on the machine rather than only users who are logged on.
- Per-user modules run only for profiles that hold the artefact, so `Default` and `Public` no
  longer show up as needing review.
- On a live system without elevation, modules that need raw or admin-only access (MFT, event
  logs, prefetch, registry hives, Amcache) are skipped with a reason instead of failing or coming
  back empty.
- A tool that leaves only 0-byte files is reported as no output. EvtxECmd and Hayabusa showed
  Completed when they could not open a single log.
- Output that cannot be moved into its category folder fails the module, and the file is kept in
  `_Staging` for you. It used to count as delivered, so the module showed Completed while the
  file was deleted.
- A module that cannot create its output folder or logs fails on its own and the run carries on.
  It used to end the whole run, with no manifest written.
- RHEL's dated log rotation (`secure-20260920`) is now read by the authentication parser.
- Hayabusa's error log is kept with the run, under `_Logs\Console\ToolLogs`, instead of in the
  application folder.
- Chainsaw's progress lines are kept in its log, so an empty hunt says how many rules and logs it
  loaded.
- Dark mode, switched on Settings and remembered for your Windows account. It covers every control,
  the module options window and the title bar.
- Setup remembers where each evidence folder's output went. Choose an evidence folder you have
  run before and the output folder and case name from its last run are filled in, with a green
  note saying so. Anything less certain is amber and has to be confirmed before Run: evidence
  never run before (the default output folder is shown), a case folder that seems to have moved
  (found in the same place relative to the evidence), or a last output folder that no longer
  exists. Choosing or typing an output folder counts as confirming; otherwise Run asks first.
  Collections you renamed keep their names too, so a renamed collection is not processed again
  into a second folder under its detected name.
- A mounted Windows drive is named after the host in its own registry (the computer name in its
  SYSTEM hive) instead of `IMAGE_<letter>`. A volume with no readable hive keeps the old name.
- The Windows system summary (hostname, OS, timezone, network, accounts) now works on a live
  system too, run elevated. It saves copies of the SYSTEM and SOFTWARE hives to scratch space and
  reads those.
- The Run options on Setup (Workers, Heavy IO, Zips at once and the three ticks) are kept between
  launches. They are saved when you press Run and when you close ArtefactForge.
- A Settings tab holds dark mode, ArtefactForge updates and About, which move out of Tools. Results
  now sits next to Run. On Setup, the two Options become Module options and Run options.
- The module selector on Setup is redesigned, with two layouts to choose between on Settings.
  **List** (the default) shows each category as one row, collapsed, with a tick for the whole
  category and a note of anything switched off. Open a category to see its modules one step in,
  each with what it parses, the module name, whether it runs on live systems, collections or both,
  and its own Options button. **Rail** lists the categories down the left with a count, and shows
  the chosen category's modules on the right, described, with a switch each.
- Collections on Setup move into their own tab beside Modules, with room to review what will be
  processed: each collection's name, what it was detected as, how many of the ticked modules
  apply to it, where it comes from (with a zip's size) and the folder its output goes to.
- When the window is too short for every run option, a "More options below" button at the foot
  of Run options says so and scrolls to the rest.
- A Windows / Linux switch above the modules. Detecting evidence turns it to the evidence's
  platform; All shows both.
- Modules that will not run on the detected evidence (a live-only module against a collection,
  for example) are dimmed before the run, rather than appearing only as skips afterwards.
- Screen readers and UI automation can now reach the contents of each tab, not just the tab
  names.
- Zipped collections can be processed directly. Choose a CyLR zip (Zip on Setup, or the zip's path
  on the command line), or tick Batch on a folder holding collection folders and zips together.
  Each zip is extracted into the case's `_Extracted` folder, checked entry by entry against the
  zip's own CRC, and then parsed. Two zips are worked on at a time (Zips at once on Setup,
  `--zips-at-once`), so the next one extracts while the last finishes. An entry that fails the check
  is removed and listed in `_Logs\Extraction\<name>.csv`, and the collection is marked for review.
- "Delete extracted zips after parsing" (`--cleanup-extracted`) removes each zip's extracted data
  once its modules have finished, so a large batch only needs space for the zips being worked on.
  It is off by default. Data is kept anyway if the run is cancelled or extraction reported a
  problem. `--extract-to` puts extractions somewhere other than the case folder.
- Re-running a batch picks up where it left off.
  - A zip whose work all finished is skipped without being extracted again. That includes a zip
    whose only gap is a module that came back with no output, since a re-run would only repeat
    that answer.
  - A zip with work still to do reuses its extraction from the earlier run, if it is still there,
    and runs only what is left.
  - With "Delete extracted zips after parsing" ticked, extracted data an earlier run kept is
    deleted, including for zips that are skipped.
  - The Extract row and the run log say which of these happened.
- Velociraptor offline collections (the collector's zip) are processed like any other zip. They
  are named after the host in the collection. ArtefactForge also turns the zip into the files the
  tools expect:
  - Its separate upload roots are merged into one `C` folder.
  - Encoded file names are decoded.
  - `$UsnJrnl:$J` becomes `$Extend\$J`.
  - Sparse files, such as hives and their logs, are written back at their original size.
  The USN journal keeps only its data, without the gigabytes of empty space in front of it, so
  `OffsetToData` in its CSV counts from that data; `UpdateSequenceNumber` is the original offset.
  A collection the collector reports as unfinished or short of data is marked for review.
  Velociraptor's own files are kept in `_Velociraptor`. Shadow copies inside a collection are left
  out, and the Extract row says how many files that was.
- A Velociraptor collection that has already been unzipped is recognised and converted the same
  way, into the case's `_Extracted` folder. The unzipped folder itself is only read.
- UAC (Unix-like Artifacts Collector) collections are processed directly: its `.tar.gz`, `.tar`
  or `.zip`, or a UAC folder that has already been unpacked. The Zip button on Setup is now
  Archive and accepts all of these, and Batch picks up `.tar.gz` files beside zips and folders.
  - The collection is named after the host recorded in UAC's log, or failing that in the
    archive's name.
  - The files UAC collected (`[root]`) become the Linux root the Linux modules read.
  - UAC's own output (`uac.log`, `live_response`, `bodyfile` and the rest) is kept in `_UAC`.
  - Symbolic links are listed in `_symlinks.csv`, with their targets, rather than created.
    Windows needs a privilege to make them, and their targets point at the original system,
    not the evidence. LinuxSystemd reads enablement links from this list, and the system summary
    reads `/etc/localtime` and `/etc/os-release` from it, so neither loses those details.
  - Linux names Windows cannot hold (`aux.c`, a trailing dot, systemd's `\x2d`) are renamed and
    logged.
  - An archive that ends early or fails its gzip checksum is marked for review, and everything
    before the damage is kept.
- New LinuxLiveResponse module reads what a UAC collection's live response recorded about the
  running system. Each of these becomes a CSV:
  - Processes, with each one's executable, working directory and hashes. A Review column flags a
    deleted executable, one running from `/tmp`, `/dev/shm` or memory, a shell or download
    one-liner, and a process `/proc` showed but `ps` did not.
  - Sockets with the processes that own them.
  - Interface addresses, routes and the neighbour cache.
  - Open files, with deleted-but-open ones marked.
  - Loaded kernel modules, with their taint flags explained.
  An index lists every live response file and which CSV read it, so command output that is not
  parsed (iptables, systemctl and the rest) is still in view.
- New LinuxAudit module reads the audit daemon's log (`/var/log/audit`). The records of each event
  are merged into one row, with the command line decoded and user IDs named. A key events CSV lists
  logins and failed authentication, sudo commands, account changes, audit rules being changed or
  the audit daemon stopped, and SELinux/AppArmor denials.
- New LinuxSyslog module reads the general system logs and their rotations: `syslog`, `messages`,
  `kern.log`, `daemon.log`, `user.log` and `cloud-init.log`, one row per line. The output of
  first-boot scripts in `cloud-init-output.log` gets its own CSV. Key events pick out:
  - cron jobs run,
  - USB devices connected,
  - unsigned and out-of-tree kernel modules,
  - crashes and out-of-memory kills,
  - interfaces set promiscuous.
- New LinuxPersistence module covers persistence and tampering points beyond cron and systemd:
  - `ld.so.preload`, `rc.local`, and shell startup files for the system and each user,
  - MOTD scripts, which run at every SSH login,
  - XDG autostart and user systemd units,
  - `sshd_config` and `~/.ssh/rc`, and PAM,
  - kernel modules loaded at boot, modprobe install commands, udev RUN rules and APT hooks,
  - SysV init scripts.
  Every file found is listed with its modification time. Lines that do something are listed with a
  Review note, for example a download, inline code, a library preload, a non-standard PAM module,
  or root login allowed with a password.
- LinuxUserFiles now also reads what other tools remember, into `<user>_LinuxUserFiles_OtherHistory.csv`:
  - vim's commands, searches and files edited, with times where vim recorded them,
  - less searches and shell escapes,
  - mysql, psql, sqlite, node, redis-cli and irb history,
  - wget's list of HTTPS hosts,
  - the desktop's recently used files,
  - Ubuntu's marker for a user's first successful sudo.
- New LinuxExecutableHashes module merges a UAC collection's executable hash lists into one row per
  file, ready to check against a hash set. Files in temporary or hidden folders are marked.
- New LinuxChkrootkit module turns chkrootkit's output into one row per check. INFECTED, WARNING
  and suspicious-file results are marked for review.
- New LinuxBodyfile module builds a filesystem timeline from the bodyfile in a UAC collection, the
  way mactime does. Each file gets one row per distinct time, oldest first, with MACB flags,
  link targets, and user and group names. Times are UTC.
- In batch, a folder named the same as a collection zip beside it (`HOST01` next to
  `HOST01.zip`) is taken as the zip's extracted copy and skipped, so the collection is processed
  once, from the zip. The skip and its reason are shown on Setup and on the command line.
- ChainsawSrum no longer runs by default; tick it in the module list to include it. It took
  2-5 minutes per collection on its own, at the end of every collection, and SrumECmd already
  parses the same SRUM database.
- Encrypted zips are named as such, rather than reported as unrecognised evidence.
- Check for updates now reads the releases of this GitHub repository, beta pre-releases included,
  and offers the highest version. Releases are still signed, and nothing is offered until a
  release is published there; until then the check says so.
- A full disk while a tool's log is being written fails that module, with the reason, instead of
  closing ArtefactForge.
- Chainsaw and Hayabusa run one at a time, as each can take several GB: three at once ran a
  16 GB workstation out of memory. They start straight away and run beside the other modules, so
  they are not left queued until the end.
- SrumECmd no longer changes the evidence. It replays SRUM's transaction logs into the database
  it opens, which rewrote `SRUDB.dat` and its logs in the collection. The `sru` folder is now
  copied to scratch space first and parsed there; the output is unchanged.
- The ChainsawShimcache module is withdrawn for now. Chainsaw (2.16.3 and 2.16.5) stops with
  "input is out of range" on current Windows 11 Amcache hives. ShimCache is still parsed by
  AppCompatCacheParser.
- Hayabusa and Chainsaw can be updated from the Tools tab. After Check for updates, each tool has
  an Update button: it asks first, downloads the Windows release from GitHub, checks it against
  the SHA-256 GitHub publishes, installs it under the name modules use (`hayabusa.exe`), and
  records the new version and hashes in `Tools\VERSIONS.txt`. A tool that is in use, or a download
  that does not match, leaves the old version in place. Hayabusa's rules and config are replaced
  with the release's; Chainsaw's rules, sigma and mappings are kept.
- The "Open release page" buttons open the release in your default browser; they did nothing
  before. Before a check they open the latest release.
