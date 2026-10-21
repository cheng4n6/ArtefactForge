- Changed: memory-heavy modules no longer always run one at a time. They share the memory free
  when the run starts, each counted at its measured peak, so MFTECmd, Hayabusa and Chainsaw run
  side by side on a typical workstation while two of Chainsaw's SRUM analysis never do. The
  budget used is in the manifest.
- Changed: the memory-heavy module that took longest when the case last ran starts first, and
  Chainsaw now starts before Hayabusa on a first run.
- Changed: MFTECmd_MFT is now memory-heavy (about twice the $MFT in memory, 2.4 GB for a 1.2 GB
  $MFT) and ChainsawGaps no longer is (30 MB), from measurements on a 2 GB collection.
