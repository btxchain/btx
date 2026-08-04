# Bounded CUDA Profile-1 soak (pre-ratification)

Status: **completed clean — 45 minutes, 38 scenarios, zero failures.** This does
not claim roadmap gate 7 (multi-day, multi-peer testnet); the harness says so
itself and `gate7_multi_day_multi_peer_claim` is `false` in the summary.

Freeze `c7e7711e655859d5b17ab3c79666399df07f7ef2`, fingerprint
`174436c75da89fb8b7ee6a2c1a9045ff32cbeeb623f72defce82336b24b2be62`, on
Blackwell-class `sm_120`, two local regtest peers crossing the RC boundary.

## Scenarios exercised

| scenario | runs |
| --- | --- |
| `relay` — mine on A, require tip match plus relay telemetry on B | 31 |
| `competing_branch` — disconnect, mine divergent tips, reconnect, converge | 2 |
| `restart` — stop/start B, re-check the CUDA canary and tip catch-up | 2 |
| `cache_persist` — after restart require the CUDA provider and mine again | 2 |
| `ibd_boundary` — stop B, mine a lag on A, restart B and sync | 1 |

Zero `fail`/`error` events across the whole run.

The `restart` and `cache_persist` scenarios are the ones worth noting: they
cross a process boundary, which is exactly where the durable
`BLOCK_EXACT_REPLAY_VERIFIED` verdict and its consensus-context binding are
exercised. The `ibd_boundary` scenario covers the catch-up path that the
RC-admission bypass fix addresses.

## What this run also demonstrated, incidentally

`events.sanitized.log` is **non-empty**. Until this campaign the soak's
sanitizer read its own program from stdin, so every "sanitized" evidence file
was written empty while the gate appeared to pass. This is the first run whose
sanitized output actually contains the run.

## What it does not cover

Multi-day wall clock, multi-peer public or testnet topology, upgrade behaviour
across release binaries, DoS admission storms, ASERT calibration campaigns, and
any ratification or activation flag. Toy dimensions with `auto-fallback`, not
production dims — this is a lifecycle/liveness soak, not a performance claim.

## Artifacts

- `soak-summary.json` — machine-readable summary, provenance-stamped.
- `events.sanitized.log` — the sanitized event stream.

Machine-class data only: no hostname, account name, filesystem path, device
serial, network address, or credential. `check-public-evidence.py` passes.
