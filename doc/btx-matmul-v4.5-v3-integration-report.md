# V3 integration report (Wave 2–5 scaffold status)

## Implemented on `wip/v45-production-coupled`

- V3 parameter hypothesis + honest packed/int8 sizes
- MAC = 12 TiMAC for V3; packed-bank helpers + tests
- Derived `peak_ready` (never true without all prerequisites)
- CUDA episode full-schedule page accumulation (medium digest parity)
- SM120 packaging preserved
- Docs: spec, packed audit, adversarial, GKR OPEN, measurement protocol, JSON schema

## Still OPEN / not production-complete

| Item | Status |
|------|--------|
| Full device-resident perm/mix/exchange/Extract/digest | PARKED (host barrier tail remains) |
| Real material exchange (4 GiB digest-affecting) | OPEN / decorative domain tag |
| True Q batching without slot-0 serialize | OPEN |
| SM100 native tcgen05 recipe | compile-isolated only; peak false |
| GKR fabricated-witness soundness | OPEN/PARKED; arbiter OFF |
| B200 / RTX 5090 matched economics | NOT RUN → PLAUSIBLE BUT UNMEASURED |
| Activation | inert (`INT32_MAX`) |

## Screenshot economic claim

**PLAUSIBLE BUT UNMEASURED** (blocked on silicon + optimized Streamed adversarial measurements).
