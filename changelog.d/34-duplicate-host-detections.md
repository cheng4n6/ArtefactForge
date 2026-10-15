- Fixed: the case report counted a host's detections twice when the host was collected more
  than once into the case (two folders whose system summaries give the same hostname). Each
  rule now counts the higher of the collections' hits instead of their sum, so the Detections
  section and the critical and high cards match a single collection. A host collected more than
  once is marked "Collected N times" in the Hosts section and raised under "Needs attention",
  and the header and Hosts count it as one host.
