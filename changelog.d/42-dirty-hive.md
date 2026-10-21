- **Registry:** a dirty hive collected without its .LOG1/.LOG2 files is no longer skipped in
  silence. Amcache, ShimCache, ShellBags and RECmd read it as last written to disk and flag the
  module for review, as recent entries may be missing. Re-run them on affected collections.
