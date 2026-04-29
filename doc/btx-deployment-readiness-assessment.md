# BTX Deployment Readiness Assessment (Rev 2)

**Date**: 2026-02-17
**Reviewer**: Claude (static code analysis against actual source)
**Branch**: `claude/review-deployment-readiness-31AOK` (merged from `main` at `ad27a65`)
**Method**: Line-by-line source code analysis. No build/test execution (container
lacks boost-dev/libevent-dev headers and has no network access).

---

## Executive Summary

**Verdict: NEAR PRODUCTION-READY — 7 concrete fixes required.**

After merging from `main`, the CTV+CSFS implementation is now **complete in code**
(my prior assessment that it was missing was wrong — it was merged between the
initial review and this revision). The core chain infrastructure is
functionally complete: MatMul PoW consensus, P2MR post-quantum signatures,
CTV+CSFS covenant/oracle opcodes, wallet/descriptor/PSBT integration, and
genesis configuration are all implemented with test coverage.

The remaining fixes are **small and well-scoped** — no architectural work is needed.

---

## Definitive Fix List

### Must-Fix Before Launch (5 items)

#### FIX-1: Testnet4 bech32 HRP collision with Bitcoin testnet

**File**: `src/kernel/chainparams.cpp:422`
**Issue**: `CTestNet4Params` sets `bech32_hrp = "tb"`, which is Bitcoin's testnet
HRP. Testnet3 correctly uses `"tbtx"` (line 310). This means BTX testnet4
addresses are indistinguishable from Bitcoin testnet addresses, causing
potential cross-chain confusion and fund loss.
**Fix**: Change to `"tbtx4"` or `"tbtx"`.
**Severity**: HIGH — address collision between chains.

#### FIX-2: Regtest bech32 HRP collision with Bitcoin regtest

**File**: `src/kernel/chainparams.cpp:714`
**Issue**: `CRegTestParams` sets `bech32_hrp = "bcrt"`, which is Bitcoin Core's
regtest HRP. While regtest is not a public network, this creates confusion in
development/testing when both Bitcoin and BTX regtest nodes are running.
**Fix**: Change to `"btxrt"`.
**Severity**: MEDIUM — developer confusion, not user-facing.

#### FIX-3: Signet uses Bitcoin's genesis block and parameters

**File**: `src/kernel/chainparams.cpp:527-529`
**Issue**: `SigNetParams` creates the genesis block via `CreateGenesisBlock()`
(Bitcoin's genesis) instead of `CreateBTXGenesisBlock()`. It uses Bitcoin's
original timestamp, nonce, BIP heights at 1, and `bech32_hrp = "tb"`. If BTX
ever runs a signet, this would create a chain that looks like Bitcoin signet.
**Fix**: Either convert to BTX genesis/parameters, or explicitly document that
BTX signet is unsupported and add a startup error/warning if `--signet` is used.
**Severity**: MEDIUM — latent issue, not blocking if signet is unused.

#### FIX-4: `P2MR_SCRIPT_FLAGS` missing `SCRIPT_VERIFY_CHECKSIGFROMSTACK`

**File**: `src/test/pq_consensus_tests.cpp:29-31`
**Issue**: The test constant `P2MR_SCRIPT_FLAGS` includes
`SCRIPT_VERIFY_CHECKTEMPLATEVERIFY` but omits `SCRIPT_VERIFY_CHECKSIGFROMSTACK`.
While CSFS is sigversion-gated (not flag-gated) so this doesn't cause test
failures, the consensus flags in `GetBlockScriptFlags()` (validation.cpp:2662)
include both flags. The test flags should match what consensus actually uses.
**Fix**: Add `| SCRIPT_VERIFY_CHECKSIGFROMSTACK` to `P2MR_SCRIPT_FLAGS`.
**Severity**: LOW — correctness issue in test code only, not consensus.

#### FIX-5: CSFS SLH-DSA and SLH-DSA delegation paths have zero test coverage

**Files**: `src/test/pq_policy_tests.cpp`, `src/test/pq_consensus_tests.cpp`
**Issue**: The policy code defines 9 leaf templates. Two have zero test coverage:
- `CSFS_SLHDSA` (pure SLH-DSA oracle leaf) — never instantiated in any test
- `CSFS_VERIFY_CHECKSIG_SLHDSA` (SLH-DSA delegation) — never instantiated in
  any test

The ML-DSA variants of both are well-tested. The SLH-DSA paths share most code
but diverge in pubkey parsing, signature size validation, and validation weight
charging. An undetected regression here could silently reject valid SLH-DSA
oracle transactions on mainnet.
**Fix**: Add unit tests for both template types (straightforward copies of the
ML-DSA tests with SLH-DSA keys — ~30 lines each).
**Severity**: MEDIUM — untested code path in consensus-critical policy enforcement.

### Should-Fix Before Launch (2 items)

#### FIX-6: `btx-genesis` tool uses KAWPOW hashing, not MatMul

**File**: `src/btx-genesis.cpp:406,437`
**Issue**: The genesis mining tool calls `kawpow::Hash()`. The consensus code
(`CheckMatMulProofOfWork_Phase1` in pow.cpp:350-352) explicitly bypasses all
PoW validation for the genesis block via:
```cpp
if (block.hashPrevBlock.IsNull()) return true;
```
This means the genesis block is validated solely by the hardcoded hash assertion
in chainparams.cpp. The zeroed `matmul_digest`/`seed_a`/`seed_b` fields are
never checked — this is **by design and correctly implemented**.

**However**, the `btx-genesis` tool is now functionally useless for the
production chain because it mines with the wrong algorithm. Post-genesis block 1+
mining requires MatMul proof, and there is no standalone MatMul mining tool
outside the node's `getblocktemplate`/`submitblock` RPC flow.

**Fix**: Either (a) update `btx-genesis.cpp` to optionally use the MatMul solver
for consistency and future genesis re-mining, or (b) document that genesis PoW
is intentionally KAWPOW and the tool is genesis-only.
**Severity**: LOW — genesis block validation is correct as-is. This is a tooling
completeness issue.

#### FIX-7: Mainnet genesis timestamp rerolled to launch window

**File**: `src/kernel/chainparams.cpp:158`
**Status**: Completed
**Update**: Genesis `nTime` is now `1771726946` (Feb 22, 2026 02:22:26 UTC),
and dependent frozen tuples/hash assertions were regenerated.
**Severity**: LOW — cosmetic/conventional, now resolved.

---

## Corrected Findings (vs Rev 1)

### Previously Reported as CRITICAL — Now Resolved

**CTV + CSFS "not implemented"**: **WRONG.** After merging from `main` at
`ad27a65`, CTV+CSFS is fully implemented:

- `src/script/ctv.h`: `ComputeCTVHash()` declaration
- `src/script/interpreter.cpp:615-643`: `OP_CHECKTEMPLATEVERIFY` handler
  (flag-gated, P2MR sigversion only, no-pop stack semantics, 32-byte hash check)
- `src/script/interpreter.cpp:1197-1244`: `OP_CHECKSIGFROMSTACK` handler
  (sigversion-gated, `TaggedHash("CSFS/btx")`, algorithm auto-detection from
  pubkey size, validation weight deduction)
- `src/script/interpreter.cpp:1614-1634`: `ComputeCTVHashImpl()` with correct
  84/116-byte preimage, reusing BIP-341 sub-hashes
- `src/script/interpreter.cpp:1586-1601`: CTV precompute in `Init()` with
  unconditional `m_ctv_ready` flag
- `src/script/interpreter.cpp:1962-1969`: `CheckCTVHash()` with null-safety
  via `HandleMissingData()`
- `src/script/interpreter.h:148,151`: Flag definitions at bits 21 and 22
- `src/script/script.h:213-218`: Opcode definitions (CTV=0xb3, CSFS=0xbd)
- `src/script/script.h:64-70`: Validation weight constants (ML-DSA=500, SLH-DSA=5000)
- `src/script/script_error.h:90-91`: `SCRIPT_ERR_CTV_HASH_SIZE`, `SCRIPT_ERR_CTV_HASH_MISMATCH`
- `src/policy/policy.cpp:78-229`: 9-template P2MR policy enforcement with
  CTV/CSFS leaf standardization
- `src/script/descriptor.cpp:1471+`: `MRDescriptor` with CTV/CSFS leaf types
  (`ctv()`, `ctv_pk()`, `csfs()`, `csfs_pk()`)
- `src/script/sign.cpp:506-630`: P2MR signing for all 5 leaf types
- `src/psbt.h:54-59,229-237`: PSBT key types 0x19-0x1F for P2MR fields
- `src/validation.cpp:2662`: Both flags in `GetBlockScriptFlags()`
- `src/policy/policy.h:153-154`: Both flags in `MANDATORY_SCRIPT_VERIFY_FLAGS`
- `test/functional/feature_p2mr_end_to_end.py`: CTV relay, CTV CPFP, CSFS
  policy, delegation, reorg, high-load block tests
- `src/test/pq_consensus_tests.cpp`: 23+ CTV tests, 15+ CSFS tests
- `src/test/pq_phase4_tests.cpp`: 9+ signing/PSBT roundtrip tests
- `src/test/pq_policy_tests.cpp`: 22 policy tests
- `test/lint/lint-op-success-p2tr.py`: Safety lint for P2MR opcodes in tapscript

**Genesis block "PoW mismatch"**: **OVERSTATED.** The genesis block bypass in
`CheckMatMulProofOfWork_Phase1` is explicit and correct — the code comment says
"Genesis is statically embedded and does not carry mined MatMul transcript fields."
The genesis block is validated by hardcoded hash assertion, not by PoW
verification. This is the same pattern Bitcoin Core uses. Downgraded from
CRITICAL to LOW (tooling completeness).

---

## What IS Complete and Verified (by code analysis)

### Consensus Layer

- MatMul PoW: Full implementation with 2-phase validation, field arithmetic
  over M31, DGW difficulty adjustment, per-network dimension params
- P2MR witness v2: Complete dispatch with `MAX_P2MR_SCRIPT_SIZE` (10,000 bytes)
  and `MAX_P2MR_ELEMENT_SIZE` (10,000 bytes) enforcement at both push sites
- CTV: Flag-gated (OP_NOP4 fallback), 84/116-byte preimage, sub-hash reuse
  from BIP-341, null-safe CheckCTVHash
- CSFS: Sigversion-gated (P2MR only), `TaggedHash("CSFS/btx")` with `.write()`
  (not `<<`), algorithm auto-detection from pubkey size
- Validation weight: ML-DSA=500, SLH-DSA=5000, deducted before verification
- Script flags: Both CTV/CSFS flags in `GetBlockScriptFlags()` at all heights
  and in `MANDATORY_SCRIPT_VERIFY_FLAGS`
- Error codes: `SCRIPT_ERR_CTV_HASH_SIZE`, `SCRIPT_ERR_CTV_HASH_MISMATCH`
  defined and mapped in `ScriptErrorString()`
- `SCRIPT_VERIFY_END_MARKER` correctly positioned after both new flags

### Chain Parameters

| Parameter | Mainnet | Testnet3 | Testnet4 | Regtest |
|-----------|---------|----------|----------|---------|
| MatMul dim | 512 | 256 | 256 | 64 |
| MatMul enabled | true | true | true | true |
| P2MR-only outputs | true | true | true | false |
| Block time | 90s | 90s | 90s | 90s |
| Fast mine phase | 50k blocks | 50k | 50k | 0 |
| Halving | 525,000 | 525,000 | 525,000 | 150 |
| Initial reward | 20 BTX | 20 BTX | 20 BTX | 20 BTX |
| Max supply | 21M | 21M | 21M | 21M |
| Bech32 HRP | `btx` | `tbtx` | **`tb`** ⚠ | **`bcrt`** ⚠ |
| Genesis hash | verified | verified | verified | verified |
| Merkle root | verified | verified | verified | verified |

### Policy Layer

9 standardized P2MR leaf templates:
1. `CHECKSIG_MLDSA` — ML-DSA direct signature
2. `CHECKSIG_SLHDSA` — SLH-DSA backup signature
3. `CTV_ONLY` — Template hash (stack size 2)
4. `CTV_CHECKSIG_MLDSA` — Template + ML-DSA (stack size 3)
5. `CTV_CHECKSIG_SLHDSA` — Template + SLH-DSA (stack size 3)
6. `CSFS_MLDSA` — Oracle ML-DSA (stack size 4)
7. `CSFS_SLHDSA` — Oracle SLH-DSA (stack size 4) **⚠ untested**
8. `CSFS_VERIFY_CHECKSIG_MLDSA` — Delegation (stack size 5)
9. `CSFS_VERIFY_CHECKSIG_SLHDSA` — SLH-DSA delegation (stack size 5) **⚠ untested**

### Wallet/Descriptor/PSBT

- `mr()` descriptor with 5 leaf types (CHECKSIG, CTV_ONLY, CTV_CHECKSIG,
  CSFS_ONLY, CSFS_VERIFY_CHECKSIG)
- Deterministic PQ key derivation from secp256k1 seeds
- P2MR signing for all 5 leaf types with `SignatureData` extension
- PSBT key types: 0x19-0x1F (input), 0x08-0x09 (output)
- Full PSBT serialization/deserialization roundtrip
- PSBT combine support for multi-party P2MR workflows

### Test Coverage Summary

| Component | Unit Tests | Functional Tests | Coverage |
|-----------|-----------|-----------------|----------|
| MatMul PoW | pow_tests, matmul_* | mining readiness | Full |
| P2MR consensus | 47+ pq_consensus_tests | feature_p2mr_end_to_end | Full |
| CTV consensus | 23 tests | CTV relay + CPFP | Full |
| CSFS consensus | 15+ tests | CSFS policy rejection | Full (ML-DSA); **Gap (SLH-DSA)** |
| Policy | 22 pq_policy_tests | End-to-end relay | Full (ML-DSA); **Gap (SLH-DSA)** |
| Descriptors | 149+ pq_descriptor_tests | RPC wallet | Full |
| Signing/PSBT | 9+ pq_phase4_tests | — | Full |
| Genesis | genesis freeze verification | Launch blockers CI | Full |

---

## Conclusion

This March 5 assessment is historical context only. The reset-chain launch
decision is now governed by the later verified SMILE-default state in
`doc/btx-shielded-production-status-2026-03-20.md` and
`doc/btx-smile-v2-genesis-readiness-tracker-2026-03-20.md`.

So the old conclusion here is superseded: this document should no longer be
read as the current launch sign-off for the shipped shielded architecture.
Use the March 20 production-status and genesis-readiness documents for the
current reset-chain protocol, benchmark numbers, and verification surface.
