### Features

* **Evidence lake:** build it from ArtefactForge. Tick "Build evidence lake when the run finishes" in the run options (`--lake` on the command line), or use Build evidence lake on the Analysis tab's Overview, which shows when the lake was built, how many hosts and timeline rows it holds, and anything that needs a look. `ArtefactForgeCli lake build <case>` builds it without a run. Cases processed before this version get each host's outputs.json written first, from the files and the last run's manifest. The case report has an Evidence lake section once a lake has been built.
