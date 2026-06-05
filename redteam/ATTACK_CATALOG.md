# BTX Attack Catalog (living document)

Taxonomy of adversarial vectors against BTX (MatMul PoW + ASERT + shielded). Each item:
status (UNTESTED / TESTING / CONFIRMED / REFUTED), owner, and a one-line hypothesis.
Inspired by known attacks on PoW/difficulty/privacy chains, adapted to this design.

## A. Timestamp / difficulty (consensus) — PR #214 surface
- A1 Future-drift grind to MAX cap (per-block) — owner a1. Half-life == drift == 3600 ⇒ a single
  maxed block can move difficulty ~×2. CONFIRMED loose per-block lever.
- A2 MTP-ratchet / cumulative future drift — owner a1/a2. cap = prev_MTP+3600, MTP is median(11)
  so maxed blocks pull MTP forward, raising the next cap. BUT bounded by MAX_FUTURE_BLOCK_TIME
  (block.time ≤ local_clock+7200) ⇒ total lead over real time ≤ 2h. Hypothesis: bounded transient,
  not unbounded. Mitigation candidate: cumulative windowed future-drift cap.
- A3 Backward-time / oscillation asymmetry — owner a6. Fix caps future only. Does past-dating
  (block.time>prev_MTP, minimal gap) let net difficulty suppression or profitable oscillation?
  VERIFY the SIGN of ASERT response first (small gap ⇒ diff UP expected). BIP94 present.
- A4 Timelock maturation via MTP inflation (BIP113) — owner a2. Inflated MTP matures nLockTime/CSV
  outputs early ⇒ spend time-locked funds prematurely.
- A5 Liveness: does the cap reject honest blocks after a real hashrate stall? owner a1. Should clamp, not stall.
- A6 ASERT anchor / boundary manipulation — owner b4. Anchor block, retune heights (int32max=off),
  half-life upgrade height, genesis/early-height special cases, integer overflow in target calc,
  reorg across a boundary height.
- A7 Difficulty-raising attack to orphan competitors — owner b5. Minimal-gap block spikes next
  difficulty; combine with selfish mining to suppress others, then drop difficulty for yourself.

## B. MatMul PoW soundness (NOVEL — crown jewels)
- B1 **Freivalds false-positive forgery** — owner b1. STATUS: REFUTED (see LEARNINGS). Fiat-Shamir binds r to C'; 2^-62 sound; C' header-committed. Not forgeable. Verification: sigma=DeriveSigma(block) (from
  attacker header+nonce) → noise::Generate(sigma,...) seeds the Freivalds challenge. If the challenge
  is fully determined by grindable block data, can an attacker grind the nonce so a FAKE C'≠A·B passes
  the probabilistic check (error<2^-62 per round; nMatMulFreivaldsRounds rounds)? If yes ⇒ counterfeit
  PoW with ~0 matmul work ⇒ catastrophic. Check: rounds count, whether challenge r is re-derivable/biasable,
  domain separation, whether C' is committed in header (merkle/seed) or free in payload.
- B2 Verification-asymmetry DoS / out-of-bounds block fields — owner b2. matmul_dim is a per-block field.
  Pathological dims (0, 1, not multiple of transcript_block_size, huge near limits), oversized/short
  Freivalds product payload, malformed seeds, dual-nonce (nNonce64 vs nNonce) mismatch, nBits at powLimit
  boundary. Goal: force honest verifiers into huge CPU/memory (O(n^2)/O(n^3)) or crash/assert (cheap to make, expensive to verify).
- B3 Pre-hash sigma lottery shortcut — owner b3. Pre-hash gate: sigma ≤ target<<epsilon_bits. Can a miner
  grind cheap sigma to skip/shortcut the expensive matmul, or create verify-asymmetry? Interaction of the
  NEW header-level gate with header relay (a3). Is sigma cheap to compute vs full PoW?
- B4 PoW grinding / structure in SharedFromSeed / noise::Generate — owner b1/b3. Algebraic structure that
  lets cheaper-than-intended solving (ASIC/GPU asymmetry, low-rank shortcuts, precomputation).

## C. P2P / relay / DoS — PR #214 touched this
- C1 Product-payload griefing via BLOCK_MUTATED re-download loops — owner a3.
- C2 Non-canonical product-payload rejection orphaning honest blocks (immediate, not height-gated) — owner a3.
- C3 Header pre-hash 'high-hash' gate abuse / ban-score — owner a3.
- C4 submitblock/submitSolution guard bypass / crash — owner a3.
- C5 chain_guard griefing: getblocktemplate now THROWS on pause; induce victim pause via peer manipulation — owner a7.
- C6 NTP / wall-clock skew vs MAX_FUTURE_BLOCK_TIME + MTP rule — owner a7.
- C7 Header/orphan/addr flooding, eclipse, compact-block memory — UNTESTED (generic; lower priority).

## D. Reorg / selfish / finality
- D1 Soft-fork split: minority attacker block orphans harmlessly vs non-enforcing majority strands enforcers — owner a4.
- D2 Activation boundary off-by-one (height 199 vs 200) — owner a4.
- D3 Selfish mining tuned to ASERT (low-difficulty windows) — owner b5.
- D4 Time-bandit / deep-reorg economics incentivized by ASERT difficulty drops — owner b5.

## E. Economic / mempool (generic; "every parameter")
- E1 Coinbase subsidy/maturity edge cases, fee manipulation, RBF/pinning, mempool flooding — UNTESTED.
- E2 Block weight / serialized-size boundary (24M) — UNTESTED.

## F. Shielded / privacy (separate domain — note, not primary "evil miner" focus)
- F1 Nullifier reuse / shielded double-spend; commitment-tree manipulation; bridge view-grant abuse — UNTESTED/NOTED.

## G. AGGRESSIVE / FORGOTTEN / REGRESSION vectors (wave d — evil-miner, profit+mayhem)
- G1 **Historical inflation/DoS CVE regression sweep** — owner d1. Test classic Bitcoin bugs a fork may have reintroduced: CVE-2010-5139 (output value-sum int64 OVERFLOW / MoneyRange), CVE-2018-17144 (DUPLICATE-INPUT inflation + assert-DoS — is CheckTransaction's vin-dup check intact after the MatMul/shielded refactor?), CVE-2012-2459 (merkle DUPLICATE-txid block malleability — the PR touched BLOCK_MUTATED), BIP30/34 duplicate coinbase (CVE-2012-1909), BIP66 strict-DER / sig malleability, coinbase subsidy/halving off-by-one, INVDoS (CVE-2018-17145 orphan mem).
- G2 **FORK-BASE STALENESS** — owner d1. Determine which upstream Bitcoin Core version BTX forked from (subversion says /BTX:0.30.1/ but that's BTX's own number — find the real Core base via features/files/copyright). Enumerate Core SECURITY fixes released AFTER that base that are MISSING here (e.g. recent net_processing / blocktxn / headers-sync / miniupnp DoS CVEs). Missing upstream patch = live regression.
- G3 **MatMul BACKEND NON-DETERMINISM → consensus split** — owner d2. Repo ships CPU/Metal/CUDA/MLX matmul backends (btx-matmul-*-bench, src/matmul). If ANY two backends produce a different result/validity for the SAME block (float vs integer, SIMD reassociation, op-ordering, overflow, GPU rounding), a miner crafts a block valid on backend A, invalid on B → targeted CHAIN SPLIT across the network. Audit: is consensus verification pinned to ONE deterministic integer path, or can the active backend differ between nodes? Any float in consensus (difficulty, matmul, shielded)?
- G4 **Verification-cost amplification / resource exhaustion** — owner d3. Force honest nodes/miners to do disproportionate work: many competing low-work chains/headers each forcing MatMul O(n^2)/O(n^3) verification; the O(n^3) transcript FALLBACK path reachability at mainnet n=512 (134M ops/block); repeated noise::Generate; forcing the shielded-commitment-index "rebuild from tip" (~25min, observed); index/disk/mempool bloat; IBD/reorg verification cost. Mayhem + damage nodes/miners.
- G5 **Miner-targeted economic attacks** — owner d4. Damage miners for profit/mayhem: selfish-timing to orphan honest blocks; chain_guard pause griefing (extend a7); difficulty manipulation to make honest miners unprofitable; AND the BTX-NOVEL matmul SERVICE-CHALLENGE mechanism (getmatmulservicechallenge / redeemmatmulserviceproof / the service-challenge registry) — economic/double-redeem/replay exploits in that bespoke subsystem.
- G6 **Shielded historical-inflation analogues** — (c5 owns monetary soundness) — adapt Zcash history: Faerie Gold (duplicate note commitments), InternalH / BCTV14 soundness (2018 counterfeiting), turnstile/value-pool monitoring. Flag to c5 if not covered.

## Known-attack inspirations to adapt
Timewarp (BIP94 present — test residue), selfish mining (Eyal-Sirer), difficulty-raising/oscillation,
51%/majority-window (small chain ⇒ low absolute threshold), eclipse (Heilman), time-bandit reorgs,
verification-asymmetry DoS (cheap-to-make/expensive-to-verify), probabilistic-verifier forgery
(Freivalds false positives), nonce/field-grinding, integer overflow at parameter bounds.
