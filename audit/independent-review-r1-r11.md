# Independent review lanes R1–R11

**These lanes were not authored by a fresh non-implementing model in this
continuation.** Cursor Task cannot select DeepSeek. A separate Codex pass was
not waited on before this handoff because the operator asked to stop and
present the report when the phase finished.

Treat the following as **coordinator self-review**, not independent sign-off.

| Lane | Classification | Finding |
|---|---|---|
| R1 Swarm | REAL | Live retrieve uses `TransferSession` + `PickRarestFirst`, but overlapping non-identical **helper** ranges are unproven. Mid-transfer seeder death NOT_RUN. |
| R1 Swarm | REAL | Piece GET now admits via `UploadSchedulerDrr`; untested under concurrent multi-peer upload contention. |
| R2 Storage | REAL | No MinIO. CloudObjectLayout vs PhysicalObjectLayout naming split remains (documented, not a second store). |
| R3 Imports | REAL | `btx-torrentd` not live; HF live HTTP not authorized. |
| R4 Search | DESIGN_CHOICE | QueryRouter sample cap 32; malicious all-ones fanout not e2e. |
| R5 Gossip | REAL | 20-peer mesh and 100k/1m/10m anti-entropy NOT_RUN. |
| R6 Erasure | REAL | `setmodelswarmhealer` does not execute repair. Per-stripe unit is real. |
| R7 Packages | DESIGN_CHOICE | Offline observation must be explicit; live funding refresh NOT_RUN. |
| R8 Wallet | DESIGN_CHOICE | SubscriptionMandate remains unsigned/prepare-only. Helper has no wallet keys. |
| R9 Compat | REAL | WITH_MODELNET=OFF and 0.34.7 mixed-binary labs NOT_RUN. |
| R10 DoS | REAL | Parser bounds exist; 10k sybil / slowloris / SSRF campaign incomplete. |
| R11 Docs | STALE | Packaged `tests/ACCEPTANCE_TESTS.md` still absent from the zip extract. |

Independent verdict: **NOT_RUN**. Do not treat this file as R1–R11 sign-off.
