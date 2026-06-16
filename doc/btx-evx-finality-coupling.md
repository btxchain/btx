# BTX as a credible settlement floor for EVX — finality coupling & reorg hardening

Status: historical design note. The v0.32.10 btx-node hardening branch supersedes
the reorg-policy assumptions in this document: default behavior is now shallow
warning plus fork-choice hysteresis, randomized equal-work tie-breaking is
default-on, and deep-reorg parking is explicit opt-in only.

## 1. Why this work exists

EVX (the clearing layer in `../evx`) treats a BTX deposit as **economically final at 6
confirmations** (`packages/contracts-bridge/.../BTXDepositVerifier.sol`,
`MIN_CONFIRMATION_DEPTH = 6`) and anchors its own state roots into BTX blocks. The original
design concern was that old BTX policy used a much deeper local reorg bound, so a reorg deeper
than 6 confirmations could invalidate an EVX deposit that already minted. The v0.32.10 branch
does not turn BTX into an EVX-finalized chain; it keeps BTX neutral and adds default-on local
warning, hysteresis, randomized equal-work tie-breaking, and service-facing settlement-safety
metadata. EVX and other services must still size confirmation policy to current BTX conditions.

### Grounding in the live chain (btxd v0.32.3, observed at height ~126,151)

Measured read-only from the running archive node, not assumed:

- **No attack in progress.** Historical `getdifficultyhealth.reorg_protection` showed the
  legacy local cap active since height 61,000, **`rejected_reorgs=0`**, and
  `deepest_rejected_reorg_depth=0`.
  Deepest fork across all 306 known chain tips = **3 blocks**; 290/306 forks are single-block
  orphans. Zero `reorg`/`bad-fork` events in debug.log. `chain_guard` healthy. Health score 86/100.
- **Block timing:** target 90 s; recent 120-block window mean 92 s, p50 68 s, **p90 193 s, p99 328 s**,
  stddev 77 s. So a 6-confirmation deposit is ~9 min mean but can stretch to 20–30+ min.
- **Hashrate is low: ~1.49 MH/s, difficulty 0.031.** This is the decisive fact: a low-hashrate
  chain is cheap to 51%-attack, so BTX **cannot lean on raw PoW depth for finality credibility**.
  The empirical "deepest fork = 3" is reassuring but is *not a guarantee* against a deliberate,
  funded attacker who could deeply reorg beyond EVX's confirmation policy and reverse a
  minted EVX deposit.

**Implication:** there is no active attack, so the correct posture is deliberate, coordinated,
neutral change — not emergency hot-deploys, and crucially **not** a BTX-side finality mechanism
that depends on any external authority (see the architecture decision below). The low hashrate
raises the stakes of getting EVX's *own* deposit-finality policy right, but that is an EVX-side
concern; BTX's job is to be a strong, neutral, permissionless PoW base.

## 2. The inviolable rule (design constraint)

EVX finality is its own HotStuff-2 BFT (verified in `../evx/services/evx-consensus-node`),
with a stake-fallback beacon, so **BTX PoW is never a dependency of EVX safety/liveness** — it
feeds only a reward lane and an anti-MEV ordering beacon. Therefore every BTX change here must:

- stay **node-local policy** (a `BlockValidationResult` non-`CONSENSUS` reject), never block on EVX;
- fall back safely to BTX-native policy if any EVX-derived input is stale/absent;
- never make BTX consensus *depend on* EVX state.

## 3. Live RPC surfaces (verified against the running node — use these exact fields)

- Reorg-protection counters: **`getdifficultyhealth` → `reorg_protection`**
  (`enabled, active, max_reorg_depth, rejected_reorgs, deepest_rejected_reorg_depth,
  last_rejected_reorg_depth, last_rejected_*`). Backed by `g_reorg_protection_*` atomics in
  `src/validation.cpp:132-134`, profile built at `src/rpc/mining.cpp:1143`.
- Peer-tip health: **`getmininginfo` → `chain_guard`** (`healthy, reason,
  recommended_action, local_tip, median_peer_tip, best_peer_tip, near_tip_peers`),
  `src/node/mining_guard.cpp`, surfaced `src/rpc/mining.cpp:4376`.

The deep-reorg alarm reads these (NOT a new surface) and the host health monitor
(`~/btx-health-monitor.sh`) alerts on `rejected_reorgs>0` or `chain_guard` divergence.

## 4. The fix set (staged)

### PR-1 — safe, node-local / policy (no consensus change, no fork)
1. **Random tie-breaking** (`-randomtiebreak`, default ON in v0.32.10): equal-work ties broken by
   `Hash(per-node-secret-seed || blockhash)` instead of first-seen `nSequenceId`. Eyal–Sirer
   selfish-mining mitigation (lowers γ toward the ~25% threshold). `nSequenceId` is in-memory
   only and never serialized, so this is **non-consensus** and deploy-safe without a fork.
   Files: `src/node/blockstorage.{h,cpp}`, `src/init.cpp`, test `validation_block_tests.cpp`.
2. **Deep-reorg alarm**: surface + host-monitor integration reading the real fields in §3.
3. **F-1 (anti-DoS) — DEFERRED (consensus-safety judgment).** The proposed fix binds the
   header-level `HasValidProofOfWork` MatMul check to a sigma upper bound. But that function is
   **height-independent** (it runs in header-sync before the connecting height is known), while the
   pre-hash epsilon is **height-dependent** (0 before activation, then 10→18). Any fixed sigma bound
   would wrongly reject valid pre-activation/old headers during IBD and break sync. F-1 is MED and
   already mitigated — forged-digest headers are caught at the contextual pre-hash gate one cheap
   `DeriveSigma` later and the peer is punished (now via the MatMul ladder, see F-3). Not worth the
   header-sync risk; left as a documented follow-up if a height-aware variant is ever warranted.
4. **F-3 (anti-DoS)**: route `bad-matmul-seeds` / pre-hash-gate header failures into the MatMul
   DoS punishment ladder (`IsMatMulPhase1Failure` classifier), not just generic 100-pt.
5. **F-4 (defense-in-depth)**: NEON-vs-scalar Freivalds `dot` startup self-test, fail-closed to
   scalar on mismatch — prevents a latent ARM/x86 divergence becoming a verify-path split.
6. **Doc-pin the 61,000 coupling constant** (this file): EVX hard-codes
   `PRODUCT_COMMITTED_ACTIVATION_HEIGHT = 61000` in three places
   (`../evx/packages/precompiles-btx/src/lib.rs`, `BTXHeaderStore.sol`, `BTXWorkVerifier.sol`)
   and it MUST stay byte-identical to btx-node `nReorgProtectionStartHeight = 61000`
   (`src/kernel/chainparams.cpp:177`). Any change to one silently breaks the EVX bridge gate.

### Architecture decision — BTX stays NEUTRAL; the gap is closed on the EVX side
Worker #75 found that an always-on hard reorg refusal is itself split-prone:
an honest partition that both sides extend past the local cap cannot reconverge
(each side sees the other as too deep and refuses), even though one is the
legitimate most-work chain. The v0.32.10 branch uses **default WARN plus
hysteresis**: follow most-work only after the extra-work rule is satisfied,
raise `DEEP_REORG_DETECTED`, and keep hard-refuse parking opt-in via
`-parkdeepreorg=1`.

An EVX-anchored finality floor — having BTX refuse reorgs below an EVX-BFT-finalized height fed
in via a `setfinalityanchor` RPC — was prototyped (merged as #246) and then **REVERTED**, because
it violates BTX's defining property:

> **BTX is the public, neutral, permissionless settlement floor. It must NOT require any
> permissioned, centralized, or EVX-specific input to operate or to decide finality.**

The floor failed that test on every count: it was **EVX-specific** (built solely for EVX), it was
**permissioned/centralized** (whoever controls the local feed controls the node's reorg
behaviour — a trusted authority deciding finality), and it **inverted the inviolable rule** by
making BTX *read EVX* when the whole architecture is that EVX reads BTX (whitepaper §9.2: BTX PoW
is never a dependency, BTX is narrow and does one thing — settle). A safe *hard* reorg floor
fundamentally needs an agreed finality point, and the only agreed points available to BTX are
either an external authority (EVX → not neutral) or a BTX-native finality gadget (does not exist).
So BTX correctly has **no hard finality floor** beyond its existing, non-EVX machinery.

### How BTX is a credible finality base for EVX — with ZERO EVX-specific/permissioned input
BTX provides credibility purely as a strong neutral PoW base. Nothing below is EVX-aware:
- **Deep-reorg WARN + hysteresis + alarm**: late branches beyond the configured
  hysteresis depth need extra work before automatic activation, and deep reorgs
  are loudly surfaced (`DEEP_REORG_DETECTED`, `getdifficultyhealth.reorg_protection`,
  `chain_guard`) so any operator — not just EVX — can act.
- **Economic finality via confirmations**: the standard Nakamoto property. Deeper confirmations =
  exponentially harder to reverse; this is what EVX (and everyone) already relies on.
- **Existing, non-EVX trust-minimisation already in BTX**: `checkpointData`, `defaultAssumeValid`,
  `nMinimumChainWork` (`src/kernel/chainparams.cpp`) — release/social-consensus anchors that are
  part of stock Bitcoin practice and carry no per-operator authority and no EVX coupling.
- **`-randomtiebreak`, MatMul parent-MTP seeding, F-3, F-4**: neutral selfish-mining,
  template-precomputation, DoS, and correctness hardening.

**The service confirmation-depth gap is closed on the EVX side, where it belongs.** EVX has its own
HotStuff-2 BFT finality and is the layer that *reads* BTX. It already reacts to BTX reorgs
(`BTXReorgManager`, the optimistic-mint 3-hour veto window, the Class-A/B confirmation gate). To
make a deposit safe against a deep BTX reorg, EVX sizes its own confirmation requirement to current
BTX reorg characteristics and risk tier, or leans on its BFT finality + veto — entirely within
`../evx`, requiring **no change to BTX**. EVX reads BTX; BTX never reads EVX.

## 5. Out of scope for btx-node (stays in `../evx`)

HotStuff-2 BFT finality; validator ranking / 1,050-BTX bond / wBTX accounting; the anchoring
**bounty payment**; the bridge deposit verifier (header/PoW/Freivalds/chainwork parsing — EVX
re-implements and only *reads* BTX); the anti-MEV ordering-beacon derivation; **and the entire
deposit-finality / reorg-safety policy** (confirmation depth, veto windows, reorg reaction). EVX's
anchoring is consensus-free — it reads the heaviest BTX chain — so btx-node need NOT recognise any
anchor format, run any EVX feed, or expose any EVX-specific RPC. The Babylon-style BTX
finality-provider tier is stubbed in EVX and imposes no btx-node requirement. **Net: BTX requires
nothing permissioned, centralized, or EVX-specific.**

## 6. Confirmed no-ops
Pre-computable templates (whitepaper issue #3): v0.32.10 extends the seed contract again.
MatMul seeds are header/nonce-bound by `DeterministicMatMulSeedV2` and, from height 130,500,
parent-hash/parent-MTP/header-bound by `DeterministicMatMulSeedV3`. Consensus re-derives and
enforces the seed for the actual parent context.
