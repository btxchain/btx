# Model / monetary isolation

The model plane MUST NOT affect:

- block validity
- fork choice
- work / difficulty
- mining priority
- transaction consensus
- ExactReplay
- issuance

If `btx-modeld` crashes, PQ sockets fail, the store is corrupt, or a GPU
qualification worker dies, monetary BTX stays up. Model RPCs fail closed.

Model traffic yields to monetary validation (do not recreate PR #135
starvation). Introduction messages (`sendmodels`, `getmdpeers`, `mdpeers`)
are size-bounded, never take `cs_main` for model work, and never insert
artifact endpoints into AddrMan.

Model ACL deny lists do not BanMan a valid monetary peer. CPU-only model
relays have zero monetary-consensus authority.

Hosting can make a node useful and economically sustainable. An additional
host is not automatically an additional independent monetary validator.
