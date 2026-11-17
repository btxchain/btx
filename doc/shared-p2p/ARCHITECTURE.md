# Shared peer core: architecture and invariants

The reusable core lives in `src/shared_p2p/core.h`. Both adapters call `ForNetwork` with the exact locally selected genesis. The singleton registry is process-local, not a distributed registry or an economic authority.

```text
BTX peers -> native monetary handshake -> SwapNet v2 admission -> signature checks
                                                       |             |
                                                       +-- shared_p2p::Core --+
                                                                             |
ModelNet peer -> strict PQ1 + native-network verification ---------------------+
                  |                                  |
           existing model data plane          service-scoped control state

Financial authority: native RPC principal -> owner mandate -> agreement grant
Chain truth: independently configured local BTX / Bitcoin / EVM verifier
Neither authority path is supplied by shared peer discovery.
```

`Core::Register` is a local software action. Policies are immutable after registration. Service names, peer IDs, queue bytes, route counts and cursors have finite bounds. `Core::Admit` accepts only local adapter results; never deserialize its authentication arguments from peer assertions.

SwapNet routes can keep multiple untrusted relays for a signature-verified identity. A relay is not the signer or liquidity owner. A first-hop attacker can still suppress messages; ACK-aware retries must explore alternatives and bounded fanout. A complete eclipse remains a residual availability risk.

ModelNet's integration enters at `GossipSearchOnSession`, after strict PQ1 and network checks. It uses shared service admission, control budget and bounded pagination cursor storage. Existing model hashes, signed provider records, pin checks, acquisition policies and storage budgets continue to govern resource use. A `publisher_identity` field is not an ownership certificate.

The generic fair-queue primitive is supplied for future incremental native data-path adoption. Existing packet framing and bulk streaming are retained in this candidate. Do not describe that as one universal wire transport. Replacing those paths must preserve backpressure, cancellation, partial-file quarantine, hash verification and recovery semantics, and requires additional native tests.
