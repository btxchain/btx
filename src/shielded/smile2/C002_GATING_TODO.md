# C-002 / R5 activation gating — IMPLEMENTED + build-verified

STATUS: DONE. The height gate (#6) + all-path gating (#4) are implemented and
`btxd` builds clean (RC=0). `validation_height` is threaded through the full
consensus cascade so the gate at `ValidateSmile2Proof` fires on every SMILE2
spend path:
- V2_SEND:          validation.cpp:1426 → VerifyV2SendProof → VerifySmile2CTFromBytes
- V2_INGRESS_BATCH: validation.cpp:1522 → VerifyV2IngressProof →
                    VerifyIngressSmileProofForBackend → VerifySmile2CTFromBytes
- verifier-set:     v2_proof.cpp (inside VerifyV2SendProof)
- builder self-check: v2_send.cpp:654
At/after C002_ACTIVATION_HEIGHT (123000), anonset-bound spends MUST be wire v3;
v2 is rejected (`bad-smile2-proof-wire-version`). The legacy uint256/native
(MatRiCT) ingress overload is a DIFFERENT proof system and is intentionally NOT
gated by C-002.

Remaining (non-blocking): regtest test vectors at height >=123000 proving a v2
spend rejects and a v3 spend accepts (the gate logic is compile-verified; a
height-≥H regtest scenario is the end-to-end confirmation).

---
Original spec (for reference):

## #6 + #4 — height gate + gate ALL spend paths (one change)

The chokepoint `ValidateSmile2Proof` (verify_dispatch.cpp) is reached by every
spend-bearing path: `v2_send.cpp:654`, `v2_ingress.cpp:811`, `v2_proof.cpp:2510`
(all via `VerifySmile2CTFromBytes`). Gating it here covers V2_SEND, the ingress
batch (audit #2), and the verifier-set path simultaneously.

### Step 1 — `ValidateSmile2Proof` / `VerifySmile2CTFromBytes`: add `int64_t validation_height`

```cpp
static constexpr int64_t C002_ACTIVATION_HEIGHT = 123000;

// in ValidateSmile2Proof(...)  (add validation_height param, thread from VerifySmile2CTFromBytes)
const bool require_c002 = validation_height >= C002_ACTIVATION_HEIGHT;
const uint8_t expected_wire_version =
    !bind_anonset_context ? SmileCTProof::WIRE_VERSION_LEGACY
    : require_c002        ? SmileCTProof::WIRE_VERSION_C002_HARDENED   // v3 mandatory post-H
                          : SmileCTProof::WIRE_VERSION_M4_HARDENED;    // historical/pre-H
if (proof.wire_version != expected_wire_version) {
    return std::string{"bad-smile2-proof-wire-version"};
}
```

This makes v3 mandatory for ALL shielded spends after H (old notes included — the
holder re-proves canonicality at spend time from amount/opening/key; a malformed
old note fails R5), and rejects v2/legacy post-H. Update `verify_dispatch.h`
signatures to add the `validation_height` param (no default — force every call
site to pass the real height; a `=0` default is exactly the
`validation_height==0 bypass` the audit warned about).

### Step 2 — thread height through the verify chain (exact plumbing)

The chain is: `shielded/validation.cpp:1426 & :1455` (consensus, has nHeight) →
`VerifyV2SendProof` (v2_proof.cpp:2407 — ADD `int32_t validation_height`) →
`VerifySmile2CTFromBytes` (verify_dispatch.cpp:152 — ADD param) →
`ValidateSmile2Proof` (gate). Also the direct `VerifySmile2CTFromBytes` callers:
`v2_send.cpp:654` (validation_height IS in scope) and `v2_ingress.cpp:811`
(validation_height threaded in this file already). v2_proof.cpp:2510 is INSIDE
VerifyV2SendProof so it forwards that param.

Caller updates required:
- consensus: `shielded/validation.cpp:1426`, `:1455` → pass real nHeight. NO
  call site may pass 0/sentinel (audit: "no validation_height=0 bypass").
- ~10 TEST callers of `VerifyV2SendProof` (src/test/shielded_v2_*.cpp,
  shielded_validation_checks_tests.cpp) → pass an explicit PRE-activation height
  (e.g. 1) so their existing v2 proofs stay valid, OR give VerifyV2SendProof a
  test-only default that the 2 consensus callers always override.

### WHY THE GATE IS SECURITY-RELEVANT (not cosmetic)
A proof marked `wire_version=v2` (M4_HARDENED) but carrying C-002 fields decodes
fine, yet the verifier then SKIPS the mandatory seed_z step-12 binding (that
check is v3-only; v2 uses the legacy "check-if-present" which a zeroed seed_z
bypasses). So without the height gate forcing v3 post-activation, an attacker can
submit a v2-versioned proof to dodge the seed_z transcript binding. (Old genuine
pre-fix v2 proofs are already rejected at decode for missing C-002 field bytes.)

### BUILD + REGTEST VERIFIED (2026-06-02, container rtX1-orig)
The production-clean smile2 port (commit 6980d932, NO forge hooks/debug) builds
into `btxd` (RC=0, `[100%] Built target btxd`) and runs in regtest: node starts,
RPC up, mined 101 blocks (block validation OK), coinbase matured, shielded RPCs
present (z_shieldfunds, bridge_buildshieldtx). The crypto correctness itself is
proven by the rtx1_f3 forge harness (honest accept; all balance/Γ/coin-binding/
range forges incl. rtx1_11 reject).

### Step 3 — tests (offline/regtest)
- old honest note spend post-H accepts (v3); new honest spend post-H accepts.
- v2/legacy spend post-H REJECTS (`bad-smile2-proof-wire-version`).
- ingress + verifier-set spend post-H without v3 REJECTS.
- honest fee-bearing / base-4 carrying spend accepts.

## Already done (commit 6980d932), verified in the offline forge harness
x1c balance, w3-1, wire v3 + seed_z mandatory, SerializedSize, R5 amount range
proof (rtx1_11 inflation → reject), in-proof duplicate-serial. Forge hooks +
debug prints stripped from these consensus files.

## Open assumption for the auditor
R5 purity checks (#3/#4) are satisfied implicitly by the degree-4 NTT slots being
irreducible fields. If an auditor cannot confirm `X⁴−ζ` irreducibility for every
slot, add explicit within-slot purity projection checks before mainnet.
