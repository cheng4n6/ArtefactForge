### Features

* **Evidence lake:** new saved query `webshell_requests` (`af-lake query <case> webshell_requests`): server scripts under an IIS site's folder with the requests to them and the processes the IIS worker started right after, listed when the worker started something, a request was flagged, or the script sits in a folder for static files; and flagged POSTs to scripts no longer on disk. Needs the WindowsIisLogs output, the MFT or USN journal, and process events (Security 4688 or Sysmon 1) for the children.
