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
