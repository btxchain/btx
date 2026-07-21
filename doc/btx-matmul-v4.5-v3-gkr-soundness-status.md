# V3 GKR / succinct verification soundness status

## Status: OPEN / PARKED — arbiter OFF

- `nMatMulRCHeight` / `nMatMulRCCoupledHeight` = `INT32_MAX`
- `EnvRCGkrArbiterEnabled` must not affect consensus acceptance on public nets
- G1–G5 fabricated-witness work remains incomplete relative to production V3 binding

## Required binding (not yet complete)

1. Header/template/nonce  
2. V3 configuration  
3. Canonical packed-bank commitment  
4. Every selected page + full 1536 coverage  
5. Every M=128 GEMM claim  
6. Accumulation / permutation / exchange / Extract  
7. Barrier roots + final digest / target  

## Fabricated-witness policy

Reject at substantive relation IDs (`v7:ground:*`, `v7:logup:*`, `coupled:column_not_grounded`, …). Final-digest-only rejects do not count as sound closure.

External cryptographic review remains mandatory before any activation discussion.
