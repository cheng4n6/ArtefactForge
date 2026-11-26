### Features

* **Evidence lake:** the IOC sweep in SQL. Building a lake on a case with an IOCs.csv now also writes IocHits.csv to `_Lake\results\IOC`, with the same hits, in the same order, as the case's own IocHits.csv: the same IOCs, hosts, modules, times, files and line numbers. MatchingLine is the row written back from the lake, so its quoting can differ from the file's. `af-lake ioc <case>` writes it without a rebuild. The IOC sweep itself is unchanged; the case's own hits will come from the lake in a later version, once the two have been compared on real cases.
