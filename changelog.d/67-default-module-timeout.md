### Changes

* **Run:** a tool whose module sets no Timeout is now stopped after 24 hours, so a tool that hangs can no longer hold a run open for ever. The module is marked Timed out and the reason says how to give it a longer limit. Modules with their own Timeout are unchanged.
