# One authoritative peer-control core across native processes

## Runtime, not just code reuse

The authoritative `shared_p2p::Core` is owned by the monetary `btxd` process and
is scoped to its exact chain genesis. SwapNet's in-process adapter and the
supervised ModelNet helper use that same runtime state. A shared header or two
process-local singletons alone would not meet this requirement.

The helper reaches the parent through `shared_p2p/broker.h`: an owner-restricted
Unix-domain socket on Unix or an owner/SYSTEM named pipe on Windows. This is
local IPC, not a new public peer listener or a hosted discovery service.

```text
                    btxd / exact genesis
    BTX peers --> SwapNet adapter -----+
                                      |
                              shared_p2p::Core
                              routes / admission
                              cursors / resource limits
                                      |
                         private local IPC broker
                                      |
                    supervised ModelNet helper
                                      |
                  existing strict PQ1 peer sessions
```

## Boundaries

The broker exposes only bounded ModelNet admission, control-message accounting,
cursor, and close operations. It has no arbitrary RPC dispatcher, wallet method,
key export, transaction authorizer, contract deployer, or peer URL dialer. Its
random credential delegates only this local helper's namespace. A peer cannot
obtain authority by putting `verified: true` in a network message.

ModelNet first completes its existing PQ1 and exact-network checks. Only the
trusted local helper reports the resulting endpoint and transport pin to the
parent. SwapNet still verifies its own domain-separated signed records and
agreement terms. Authentication profiles are not interchangeable.

Startup must create and publish the broker before launching the helper. At the
helper's executable entry, cache the credential and remove it from the inherited
environment before spawning any inference, training, or user-selected child.
A lazy cache in a gossip callback is insufficient if another child can start first.
The source integrator attempts the executable-entry edit and records whether it
found the actual entry point. The native integration review must confirm it.

The server bounds JSON size and applies an absolute I/O deadline. Unix peers are
checked against the owner's UID. Windows ACLs and remote-client rejection must
be exercised on the supported Windows toolchain; source alone is not a passing
platform test.

## Lifecycle and failure

Broker shutdown follows helper shutdown and joins its worker. Failure of this
control path must not enable financial work or weaken PQ1. New model discovery
may wait; existing verified objects and SwapNet's already-authorized chain
recovery remain under their original owners. The parent retains the core object
for the entire server lifetime.

## Actual scope of sharing

This patch shares the control core and runtime admission/routing/cursor state.
It does not replace BTX block transport with ModelNet HTTP, route model payloads
through the SwapNet worker, or downgrade ModelNet encryption. The generic fair
queue is supplied as a reusable primitive; not every pre-existing bulk/outbound
queue is migrated by this package. Do not advertise a universal single wire
protocol or whole-node bandwidth fairness until those adapters are integrated
and measured.

## Required native acceptance

Run the real two-process broker test with the checkout's UniValue implementation.
Then start `btxd` with its supervised helper and observe both namespaces from
`getswappeercoreinfo`. Verify cross-genesis/token rejection, helper restart,
credential removal before arbitrary child execution, teardown ordering, and
continued original claim/refund recovery during a helper or broker outage.
