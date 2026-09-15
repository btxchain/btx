# Community router

Normative: root addendum §4. CPU introducer, not consensus.

A router is a **CPU-capable introducer**. It is not:

- a consensus node
- a model-approval authority
- a bandwidth proxy or NAT-traversal network
- a replacement for PQ1 piece transfer

It may cache signed records (bounded) and hand validated endpoint **hints**
to the helper. An unknown hinted key stays untrusted until the operator
pins it.

`-modelrelay` on `btx-modeld` is this role: no GPU, no wallet, no payload
requirement. Monetary `btxd` may carry `sendmodels` hints; those hints have
zero monetary-consensus authority.

Discovery relays must not silently forward arbitrary TCP destinations.
