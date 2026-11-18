### Changes

* **Run:** the app now does the whole run in the background instead of on the window's own thread, so the window stays responsive during a run, most of all while a tar.gz is listed and unpacked and during the steps at the end of a run. Runs from the command line are unchanged.
