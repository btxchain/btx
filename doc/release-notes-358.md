CLI
---

- Concurrent `btx-cli lightwatch init`, `add`, and `sync` commands now serialize
  writes to the same watch directory, preventing a sync from overwriting a
  descriptor successfully added by another command. A competing writer returns
  `BTX_LIGHTWATCH_BUSY`; retry it after the first command exits. Read-only
  commands and separate watch directories remain available.
