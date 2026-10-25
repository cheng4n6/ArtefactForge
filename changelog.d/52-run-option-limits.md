- Fixed: the app now puts Workers, Heavy IO, Keep free and Zips at once in range when a run
  starts, as it already did for the saved settings. A box that is not a number, or a value that
  had to change, stops the run with a message and the box shows the value that will be used.
- Fixed: `--workers`, `--heavy`, `--zips-at-once` and `--keep-free` stop with an error when the
  value is not a number, instead of quietly using the default, and a value out of range is
  brought into range with a note saying so.
