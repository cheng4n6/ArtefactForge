### Features

* **Run:** what a run has finished is now saved as each module finishes, and the manifest is written as each host finishes, marked as not finished (`Finished` in manifest.json). A run that is closed, crashes or loses power part-way no longer starts the whole case again with Skip completed, and leaves a record of what ran.

### Bug fixes

* **Run:** when the manifest cannot be written at the end of a run (a full disk, say), the run no longer ends as "Run failed" with nothing to show. The results come back as usual, with a Manifest row for review that says why.
