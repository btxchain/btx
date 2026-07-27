# Stage-3 V1 consensus / security target

**Decision date:** 2026-07-27  
**Status:** encoded in `matmul_v4_rc_stage3_global_soundness_ledger` (recommendation #6)

## Decision

The Stage-3 V1 consensus/security target is a **64-bit security class**, with the
shipped machine-computed **global composed floor ≈ 79 bits**
(`F(q*=76)` per-site 104 minus the 25-bit site-union charge over the canonical
37.5M production sites).

This is an explicit consensus decision. It is **not** an unused 100-bit
requirement. Diagnostic FRI / recursive screens that still mention “reach 100
bits” remain inventory / uplift analysis only; they do not redefine the V1
target.

## Encoding

| Constant / field | Value | Role |
|---|---|---|
| `kV1ConsensusSecurityClassBits` | 64 | V1 security class |
| `kV1ShippedGlobalComposedFloorBits` | 79 | shipped global floor |
| `kUnusedHundredBitRequirementBits` | 100 | explicitly **not** V1 target |
| `composed_certified_bits_target` | 79 | gated mint target |
| `certified_bits` | 0 today | stays gated on readiness interlock |

## Non-goals

- Does **not** flip `certified_bits` off zero.
- Does **not** flip any readiness gate (`AggregationReady`, episode/coupled
  engines, etc.).
- Does **not** rewrite recursive/FRI 100-bit diagnostic constants in other TUs;
  those stay as uplift screens until a future consensus change.

## Evidence

`AssessExecutableGlobalSoundnessLedgerV1()` sets:

- `v1_security_target_is_64bit_class`
- `v1_global_floor_matches_shipped_79`
- `v1_unused_100bit_requirement_is_not_target`
- `v1_security_target_decision_encoded`

and the ledger note records
`v1_security_target_64bit_class_with_shipped_global_floor_79`.
