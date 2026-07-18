# BTX Proof-of-Work: v3 → v4.4 (ENC-DR MatMul) — Production Change Analysis

**Status:** decision/reference document for adopting ENC-DR as the production MatMul
consensus. Scope: everything that changes (and everything that does not) if the
current SHA-256d proof-of-work (v3) is replaced at a single activation height by the
v4.4 ENC-DR ("digest-only recompute") MatMul proof-of-work.

---

## 0. Executive summary

BTX **v3** is a classic Bitcoin-style **SHA-256d** proof-of-work: mining is raw
hashing, a block is verified with a single hash, and security tracks **hashrate**.

BTX **v4.4 (ENC-DR)** replaces the hash lottery with a **deterministic exact
integer matrix-multiplication** lottery. To find a block a miner must perform a
large GEMM over the prime field F_q (q = 2⁶¹−1), derived freshly from the header,
and commit a 32-byte digest of its result: `matmul_digest = H(σ ‖ Ĉ)`, with the
block valid iff `matmul_digest ≤ target`. Because the per-nonce work *is* a large
AI-shaped GEMM, expected blocks track **AI-accelerator compute strength**, not SHA
hashrate — this is the "reward progressively more powerful AI compute, with **no
inversion**" thesis that is the entire reason for the upgrade.

Everything above the PoW is unchanged: UTXO set, transactions, script, the
headers/most-work fork-choice, the supply schedule, and the BTX network/transport
stack. The **cost** of the switch: verification is no longer one hash. A validator
either (a) checks a relayed, self-authenticating **sketch cache** with a cheap
Freivalds probabilistic test (~100–200 ms, error ≤ 2⁻¹⁸⁰) or (b), fully
trustlessly, **recomputes** the GEMM and checks the digest exactly (ε = 0; ~1–3 ms
on a GPU, ~0.8–2 s on one CPU core). **Storage does not grow**: only the 32-byte
digest is committed, so archives store **headers only** (~60 MiB/yr) instead of the
multi-TiB/yr an in-block sketch would have cost.

---

## 1. Core mechanism, side by side

| | **v3 (SHA-256d)** | **v4.4 (ENC-DR MatMul)** |
|---|---|---|
| PoW predicate | `SHA256d(header) ≤ target` | `matmul_digest ≤ target` **and** `matmul_digest == H(σ‖Ĉ_true(header))` |
| The "work" | ~2 SHA-256 compressions per nonce | one exact GEMM: `Ĉ = (U·A)(B·V) mod q`, ≈ 7.7×10¹⁰ MACs/nonce at n=4096 |
| What a nonce does | perturbs the header hash | reseeds operand **B** (nonce-fresh) → a fresh Ĉ → a fresh digest |
| Winning condition | hash lands below target | digest of the true GEMM lands below target |
| Reward tracks | SHA **hashrate** | AI **GEMM throughput / compute strength** |

---

## 2. Full change matrix

| Dimension | v3 (SHA-256d) | v4.4 (ENC-DR MatMul) | Change |
|---|---|---|---|
| **PoW primitive** | SHA-256d hash lottery | Exact integer GEMM over F_q (q=2⁶¹−1) + digest lottery | ★ fundamental |
| **What's rewarded** | Hashrate (SHA ASICs) | AI-accelerator compute (tensor-core GEMM); **no reward inversion** — bigger AI compute earns more, provably by construction | ★ the point of the upgrade |
| **Mining hardware** | SHA-256 ASICs | GPUs / AI datacenter accelerators (CUDA/Metal/HIP; FP4/INT8 tensor paths) | ★ fundamental |
| **Per-nonce miner cost** | ~2 SHA compressions | ~7.7×10¹⁰ MACs GEMM + ~0.4M SHA (XOF+digest) | ★ |
| **Committed object** | none (the hash is the work) | 32-byte `matmul_digest = H(σ‖Ĉ)` in the header | new field |
| **Header** | ~80-byte Bitcoin header | extended header (adds `matmul_digest`, operand seeds, 64-bit nonce) | format change |
| **Verification method** | 1 hash | recompute-and-check-digest (exact, ε=0) **or** cache-authenticate + Freivalds (ε≤2⁻¹⁸⁰) | ★ fundamental |
| **Verification cost (tip)** | ~µs, any device | ~100–200 ms cache-Freivalds, or ~0.8–2 s CPU / 1–3 ms GPU recompute — per block, per block-time | ↑ but ≪ block time |
| **Verification cost (bulk/IBD)** | seconds, any device | above-`assumevalid` window: ~1–2 h (16-core) / minutes (GPU) / ~1–2 d (1 core); full `-assumevalid=0`: hours (GPU/many-core) to days (1 core) | ↑↑ — the accepted tradeoff (§6) |
| **On-chain data / block (PoW)** | 0 extra | **0** extra (digest is in the header) | flat |
| **Archive storage growth** | block bodies (normal) | **headers only** for the PoW object (~60 MiB/yr); no sketch stored | ★ major win vs any in-block/segregated sketch |
| **Determinism requirement** | trivial (hash) | **exact bit-identical GEMM across CPU/CUDA/Metal/HIP** (integer-only, no float) — the load-bearing safety property; CPU reference is sole arbiter of invalidity (R1) | ★ new consensus-critical surface |
| **Soundness of "work was done"** | SHA preimage hardness | exact (recompute ε=0) or negligible (Freivalds ≤2⁻¹⁸⁰) — never a constant/probabilistic gap | equivalent-strength |
| **Difficulty** | retarget on the hash target | retarget on the digest target (ASERT, unchanged) + measurement-gated m/n **work-shape** rungs to scale compute storage-free | extended |
| **51% attack basis** | hashrate majority | AI-compute majority | reframed |
| **Light/SPV verification** | header-chain + PoW check (cheap) | header-chain + cheap cache-Freivalds when a cache peer serves; else recompute | mostly preserved via cache |
| **Networking / transport** | BTX P2P (BIP324 + PQ hybrid, Dandelion++) | **unchanged**, plus a best-effort, non-consensus `getmmsketch`/`mmsketch` cache relay | additive, optional |
| **Post-quantum posture** | SHA-256 (Grover-only) + ML-KEM transport | **identical** — SHA-256 + ML-KEM; no new crypto assumptions | unchanged |
| **UTXO / script / txs / supply** | Bitcoin-inherited | **unchanged** | none |
| **Fork choice** | most accumulated work | most accumulated (authenticated) work | unchanged in shape |
| **Activation** | n/a | single flag-day at `nMatMulV4Height`; INT32_MAX (disabled) until GO | one-time hard fork |

★ = fundamental change. ↑ = increases. ≪ = far less than.

---

## 3. Detail on the dimensions that change most

### 3.1 The PoW primitive and the reward thesis
v3's security is "someone burned SHA hashrate." v4.4's security is "someone did a
large, exact AI-shaped GEMM." The nonce reseeds operand **B**, so every nonce forces
a fresh full GEMM (no compute-less shortcut; proven, and inherited unchanged from the
v4.x work-binding assumption). Expected blocks are therefore proportional to a
miner's **GEMM throughput**, and the operand shape (b=4, m=1024, arithmetic-intensity
above commodity-GPU rooflines) is chosen so that "throughput" means **frontier
tensor-core compute** — i.e. the reward does **not invert** to favor high-clock
consumer cards or a cheap ASIC. This is the property the entire program exists to
achieve; ENC-DR preserves it **by identity** (κ = miner-floor/v4.3-floor = 1.00,
because the miner is byte-for-byte v4.3's) and, critically, decouples it from
storage so the no-inversion margin (m) can be tuned on measured silicon at **zero**
storage cost.

### 3.2 Mining hardware
v3 → v4.4 moves the mining constituency from **SHA ASIC farms** to **AI
accelerators**. Backends exist for CUDA (FP4/INT8 tensor), Apple Metal (M-series
tensor), and HIP/ROCm (MI-series MXFP4), with a CPU reference. A SHA ASIC is useless
for v4.4 mining (SHA is <1% of the per-nonce work).

### 3.3 The committed object and header
v3 commits nothing beyond the header hash. v4.4 adds a 32-byte `matmul_digest =
H(σ‖SerializeSketch(Ĉ))` plus operand-seed fields and a 64-bit nonce. The sketch Ĉ
itself is **never** in the block or the ledger — only its digest is committed. The
in-block sketch payload MUST be empty (enforced), which collapses an entire class of
"corrupt the body to poison a valid header" attacks that a carried payload would open.

### 3.4 Verification — the big change
This is where v4.4 departs most from v3 (and from Bitcoin). A block's validity is a
**pure function of the header**: `matmul_digest == H(σ‖Ĉ_true)`, where Ĉ_true is the
deterministic recompute. Two conforming strategies decide the identical predicate:
- **Recompute (canonical, ε=0):** re-derive operands from the header, recompute Ĉ,
  check the digest exactly. ~1–3 ms GPU, ~0.1–0.25 s on 16 CPU cores, ~0.8–2 s on one.
- **Cache-authenticate + Freivalds (ε≤2⁻¹⁸⁰):** a peer relays the ~8 MiB sketch
  bytes; one hash proves `H(σ‖bytes)==digest`; then the classic O(n²) Freivalds check
  (~100–200 ms). The bytes are **untrusted and self-authenticating** — a wrong cache
  fails the hash and the node falls back to recompute.

**Consensus-critical invariant (R1):** only the **CPU integer reference** may
pronounce a block *invalid* by recompute. An accelerated backend may accept-fast on a
digest match (always safe), but any mismatch **must** fall back to the CPU reference
before rejecting — no GPU/FP path may emit a "reject." This closes the one real new
risk: because verification now runs the GEMM, a divergent backend could otherwise
reject a block others accept (a chain split). The GEMM is integer-only (no floating
point anywhere on the path), so the reference is bit-identical across compilers by
construction; the residual is cross-**backend** equality, gated by golden vectors on a
new **verify-side** conformance path (not just the mine path).

### 3.5 Storage and archive
v3 stores block bodies like Bitcoin. v4.4 stores **nothing extra** for the PoW: the
digest is in the header, and the sketch is recomputable from the header forever. An
archive node therefore keeps **headers** (~60 MiB/yr) rather than the 2.67–10.7 TiB/yr
an in-block or segregated 8–32 MiB sketch would have accumulated — a 10⁴–10⁵×
reduction, and the specific problem that killed the earlier segregated/ENC-SC designs.

### 3.6 Difficulty and compute scaling
Throughput growth is absorbed continuously by the existing **ASERT** difficulty
retarget (unchanged, rescale 1/1 at activation). To scale the *work shape* over time
(reward ever-larger AI compute), the design grows **n** first (provably never inverts:
GEMM/floor ∝ n) and **m** only inside a silicon-measured window — and because only the
digest is stored, raising m/n costs **no storage**. This is the storage-free
compute-scaling that v3 (a fixed hash) and a stored-sketch design (Θ(m²) bloat) both
lacked.

### 3.7 Security model and new assumptions
- v3: SHA-256 preimage/collision hardness; 51%-by-hashrate.
- v4.4 keeps SHA-256 + ML-KEM (no new crypto), and adds two consensus assumptions:
  (i) **work-binding** — computing the true Ĉ entries requires doing the GEMM
  (the v4.x hardness assumption, unchanged); (ii) **cross-backend determinism** —
  managed by R1 + golden vectors, so a backend bug degrades to "fall back to CPU,"
  never to a split. Attack economics move from hashrate to AI-compute; the header
  spam-gate (SHA-cheap-relative-to-matmul, audit item C1) is enabled at activation to
  price header/block delivery.

### 3.8 Decentralization / validator hardware — **the accepted tradeoff**
This is the one genuine regression versus v3/Bitcoin, and it is **accepted and
documented here** as a condition of adoption:
- **Not affected:** running a node, storing the chain (headers only), and following
  the tip. Tip verification is ~100–200 ms (cache) or ~0.8–2 s (recompute) per block
  per block-time — trivial on a CPU. A CPU node is never *locked out*: recompute is
  always available.
- **Affected:** *bulk, trustless, cache-less* re-validation — bootstrapping the
  above-`assumevalid` window, or a full `-assumevalid=0` audit — is hours-to-days on
  CPU where it is minutes on a GPU, and this pressure **grows as the PoW scales m/n
  up**. Fast independent auditing of large spans favors AI silicon.
- **Mitigations (all in the design):** the sketch cache keeps CPU verification cheap
  (Freivalds grows only ∝ n²+m²) whenever honest peers serve it; `assumevalid` bounds
  trustless recompute to a recent window (same as Bitcoin); m can be capped to keep
  recompute cheaper (trading no-inversion margin); and recompute-always-available
  guarantees no operator is excluded, only slower.
- **Adoption conditions (per project decision):** (1) this tradeoff is documented
  (this section); (2) **multi-platform** trustless verification is a build requirement —
  the recompute/verify path ships on CPU (reference) + CUDA + Metal + HIP so
  independent verification is not vendor-locked, with the door open to further
  backends.

Net framing: *not* "you need a datacenter to run a node." Rather, "a CPU runs a node
fine; AI silicon is what you want to re-derive months or years of history from
scratch quickly, and that preference sharpens as the chain scales compute."

### 3.9 Networking / relay
v3's P2P is unchanged (BIP324 v2 + PQ X25519+ML-KEM hybrid, Dandelion++). v4.4 adds a
**best-effort, non-consensus** cache relay (`getmmsketch`/`mmsketch`) with
anti-amplification serving limits (per-peer token bucket, node-wide egress budget,
dedup window). It carries **no consensus weight**: a block reaches a terminal
accept/reject from the header alone, so the cache can never wedge a node (unlike the
deleted segregated-proof relay, which had hold/stall/busy-loop hazards). This is a
strict liveness improvement over both v3 (no such surface) and the interim designs.

---

## 4. What v4.4 DELETES relative to the interim (segregated / ENC-SC) attempts

ENC-DR is a **net simplification**. Compared with the designs explored on the way, it
removes: the segregated-proof store/relay/chunking subsystem (~2k lines), BIP324
24-bit-ceiling chunking, the proof-pending hold state machine and its busy-loop class,
the MUTATED/permanent-invalid classification, the relay-ready fail-closed gate, and —
versus the ENC-SC branch — the entire sum-check + Circle-FRI proof stack (the largest
consensus-normative surface ever proposed for BTX) with its FRI-parameter and
commitment-grinding hazards. It **adds** only: a digest-only predicate + recompute
path, a small best-effort cache relay, and verify-side golden vectors.

---

## 5. What stays exactly the same (Bitcoin-inherited)

UTXO model, transaction format, Script, addresses/wallets, the block Merkle structure,
the headers chain and most-work fork choice, the coin supply/subsidy schedule, mempool
policy, RPC surface (minus the deleted proof endpoints), and the P2P/transport stack.
v4.4 is a **PoW-only** change: it swaps how blocks are *found and validated*, not what
a block *contains* or how the ledger *evolves*.

---

## 6. The accepted tradeoff, restated for the record

The project **accepts** that fully-trustless, cache-independent, bulk re-validation is
CPU-expensive (and increasingly so as compute scales), in exchange for: a PoW that
rewards AI compute with no reward inversion, exact/negligible-error deterministic
verification, and flat (headers-only) storage. Acceptance is conditioned on (a) this
documentation, and (b) shipping multi-platform (CPU/CUDA/Metal/HIP) trustless
verification so no single vendor gates the ability to independently verify.

---

## 7. Migration / activation

Single flag-day hard fork at `nMatMulV4Height` (INT32_MAX / disabled until GO).
No staged interval, no dual-profile window. Blocks below the height keep v3 rules;
at and above, v4.4 rules apply. Activation is gated on: (i) the **K.2b H100/B200
no-inversion silicon measurement** (the real GO/NO-GO — it validates the reward-tracks-
compute claim), (ii) an external cryptographic/consensus review of the built code,
and (iii) L0 hard-fork ratification. A startup invariant hard-blocks any public
network from setting the height until those pass.

---

## 8. Open items / risk register (as of RC design freeze)

| Item | Status | Owner |
|---|---|---|
| No-inversion confirmed on real H100/B200 (K.2b) | **OPEN — the decisive gate** (true for every version, inherited) | silicon measurement |
| Cross-backend verify-side determinism (R1 + golden vectors) | designed; must be built + fuzzed | implementation + conformance |
| DoS budget re-tune to O(W) recompute (release-blocking) | pending measurement | implementation |
| SHA header spam-gate enabled at activation | required | implementation |
| Multi-platform trustless-verify (CPU/CUDA/Metal/HIP) | build requirement (adoption condition) | implementation |
| External cryptographic/consensus review of built code | pending | external |
| RC builds + full unit/functional suite green | in progress | this workstream |

**Bottom line:** v4.4 keeps every Bitcoin-inherited property of v3, swaps the PoW from
hash-hardness to exact-AI-GEMM-hardness (rewarding compute strength with no inversion),
holds storage flat, and pays for it with a documented, mitigated verification-cost
tradeoff — pending the silicon GO/NO-GO that proves the reward-tracks-compute claim
the whole system exists to make.
