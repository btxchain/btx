# Model relay

A model relay is **connectivity infrastructure only**.

It may: hold bounded reservations, forward opaque bytes, assist
rendezvous and hole punch, and introduce providers.

It must not: hold wallet keys, affect consensus or fork choice, sign as
an endpoint, decrypt end-to-end model traffic, qualify models, become a
canonical registry, earn mining advantage, or insert artifact endpoints into
monetary AddrMan. Automatic spend remains 0.

## Reservations (Circuit v2-inspired)

A private node asks a reachable relay to reserve capacity for a service
identity. Defaults:

- TTL 1 hour
- 32 MiB byte ceiling
- 4 concurrent connections
- 2 reservations per identity
- 8 per netgroup
- 128 global
- idle 2 minutes

Expired and idle reservations are dropped. Floods are rejected.

Suggested active reservations: 2 (3 in preservation/server mode). If relay
R1 dies, direct connections stay up; relay-only peers try R2.

## End-to-end PQ1

```
A  ↔  PQ1 application session  ↔  (relay forwards opaque bytes)  ↔  B
```

Outer control may authenticate the relay role. Inner PQ1 remains
authoritative. A relay cannot impersonate a peer (`expected_service_id`
must match). `POST /ext/relay/connect` splices TCP only after that check.

## Rendezvous

`POST /ext/rendezvous` notifies a target over an existing relay path so
both sides can exchange candidates and attempt a direct upgrade. Records
expire. There is no global rendezvous registry.
