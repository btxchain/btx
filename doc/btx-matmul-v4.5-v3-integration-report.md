# V3 integration report (Wave completion status)

## Implemented on `wip/v45-production-coupled`

- V3 parameter hypothesis + honest packed/int8 sizes (51 GiB packed / 96 GiB int8 / 12 TiMAC)
- Digest-affecting material-exchange rounds (`exchange_rounds=4` → 4 GiB R/W estimate; default 0 preserves V1/V2 goldens)
- Medium-V3 CI shape + uint64 Mix wrap + overflow bounds; golden `744fd3df…`
- CUDA device-resident barrier tail (permute / mix / ExtractMX / BarrierRoot); episode digest still host-assembled
- Independent Q-batch (no slot-0 serialize) + Streamed strategy scaffold
- SM100 fail-closed isolation probe (separate from SM120_MMA); `peak_ready` derived only
- GKR fabricated-witness suite + V3 binding work (arbiter remains OFF)
- Rack validated: CPU coupled+packed PASS; CUDA sm120-plain datacenter PASS (toy/medium digest parity)

## Still OPEN / not production-complete

| Item | Status |
|------|--------|
| Device-assembled episode digest | OPEN (host `AssembleCoupledEpisodeDigest`) |
| Native MXFP4 device-ptr lobe GEMM (WS-B) | PARKED / portable ALU in graph |
| SM100 native tcgen05 on B200 | fail-closed; no silicon evidence |
| GKR soundness → arbiter ON | OPEN; arbiter OFF; heights `INT32_MAX` |
| B200 / RTX 5090 matched economics | NOT RUN → **PLAUSIBLE BUT UNMEASURED** |
| Activation | inert (`INT32_MAX`) |

## Screenshot economic claim

**PLAUSIBLE BUT UNMEASURED** (blocked on silicon + optimized Streamed adversarial measurements).
