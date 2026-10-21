- Changed: memory-heavy modules no longer always run one at a time. A run allows one for every
  6 GB of memory free when it starts, so a typical 16 GB workstation still runs one and a large
  server runs several. The number used is in the manifest.
- Changed: MFTECmd_MFT is now memory-heavy (about twice the $MFT in memory, 2.4 GB for a 1.2 GB
  $MFT) and ChainsawGaps no longer is (30 MB), from measurements on a 2 GB collection.
