- The case report counts a host's detections once when the host was collected more than once
  into the case. Two folders whose system summaries give the same hostname had their detections
  added together, so the Detections section and the critical and high cards counted the same
  events twice. Each rule now takes the higher of the collections' counts. The host is marked
  "Collected N times" in the Hosts section, raised under "Needs attention", and counted as one
  host in the header.
