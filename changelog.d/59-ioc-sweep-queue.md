- **IOC sweep:** IOCs can be added and imported while a sweep runs. Each goes on the list at once,
  and everything added during a sweep is swept together as soon as it finishes.
- **IOC sweep:** hosts are swept side by side instead of one after another, both after each host
  of a run finishes and from the IOCs tab, within the run's Keep free memory. Sweeping four hosts
  of a 1.2 GB case went from about 15 s to 11 s.
