# Changelog

## Unreleased

- Checking for Hayabusa and Chainsaw updates shows the installed version. It said "installed
  version unknown" for tools copied into `Tools\`, because the version came only from a
  `VERSIONS.txt` that the package does not include. The version is now read from the program
  itself. The tools list and the run manifest show Chainsaw's version too, which was blank.

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
