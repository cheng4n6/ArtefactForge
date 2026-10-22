- The RDP trace and IP history read EvtxECmd's CSV several times faster: the event logs are
  scanned in blocks, and the large Payload column is read only for the events they use.
