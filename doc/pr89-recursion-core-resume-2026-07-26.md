# PR-89 Recursion-Core — Progress & Remaining-Task Report (resume guide)

> **MatMul v4.7 transition status:** historical Stage-3 handoff, retained as
> proof-engineering evidence for possible Epochs B–D. It is not an Epoch-A
> launch plan. Epoch B requires a durable proof plus Profile-1 ExactReplay;
> Epoch C retains Profile 1 under proof authority; Profile 2 is Epoch D only.
> See `doc/btx-matmul-v4.7-transition-roadmap.md`.
>
Date: 2026-07-26. Purpose: single-file snapshot to resume the PR-89 all-Fp3 arity-4
recursive-STARK succinct-proof work without re-deriving context. Host names are
genericized ("the GPU rack" = the sm_120 GPU box; "the source mirror" = the read-only
parallel-worker mirror).

## CURRENT CRUX & PATH TO PRODUCTION CANDIDATE (2026-07-26, latest)
Two lanes are the CRUX — they resolve the two biggest open unknowns, but PASSING THEM
IS NOT A PRODUCTION CANDIDATE:
- INTEGRATION TEST (lane a1937edf): does the recursion COMPOSE with REAL children?
  (real normalized role C_rho leaves -> four-slot self-similar parent aggregates+verifies
  them in-circuit -> aggregate ROOT proves+verifies -> 2-level self-similarity). Resolves
  "does the full proof work end-to-end." SCOPE = MINIMAL (4 children, 2 levels) -> proves
  the MECHANISM composes, NOT the full 341-node tree. Test:
  four_slot_self_similar_parent_consumes_real_coupled_permutation_children.
- 3-PHASE GPU (lane ad33e8979): node prove SPEED / economics (leaf-commit + LDE-NTT +
  verifier-AIR composition on REAL structured data) -> honest per-phase wall-clock.

CRUX PASSING != RC. After the crux, a production candidate STILL requires (see REMAINING
section for detail): (1) FULL 341-NODE TREE run (scale the proven mechanism; execution +
tree-orchestration glue; UNRUN); (2) g4 CTL bus (last construction; specified not built);
(3) certified_bits=79 (ledger auto-roll-up once g0-g5 close; mechanical, gated on 1+2);
(4) REAL-BLOCK end-to-end (historical harness: real v4.6 construction block+tx -> statement -> prove ->
verify <900ms; NOTHING has run a real block yet); (5) CONSENSUS + MINER integration (proof
as mandatory authority). The crux converts "will it work / can the prover meet budget"
(open risk) into "scale it + integrate it" (known engineering + execution).

STATUS: node correctness = DONE (measured GPU prove -> real AirQuotientVerify ACCEPT +
tamper-reject); prover-budget = BEING MEASURED (node ~48min leaf-only; 3-phase collapse
unmeasured); integration = BEING TESTED (real children into the aggregate).

ECONOMICS/DESIGN NOTE (settled with the project owner): the prover is GPU-accelerated and
the recursion makes proving trustlessly SPLITTABLE, so proving is a COORDINATED NETWORK
TASK in the 90s block window (e.g. ~96 GPU rigs -> ~30s if the 48-min/node figure persists),
not a single-box burden -> not fundamental recentralization (reward centralization to
fleets/pools is inherent to the reward structure and exists in matmul v3 too). The proof's
net value: cheap verify at DATACENTER-SCALE useful work (v3 is cheap all-around but caps
work size) + DECENTRALIZES validation (cheap verify -> more full nodes) + a cooperative
prover ecosystem. Trade-off: soundness becomes CONDITIONAL (ROM+CRHF+M2) vs v3 replay's
unconditional -> the certified_bits soundness MUST actually hold, and proving MUST genuinely
distribute (both being driven). Condition for the decentralization: PERMISSIONLESS proving
coordination/market.

## Where the work lives
- Branch: `claude/matmul-v4-stage3-recursion-core-af23sj` (stage3 build worktree).
  HEAD `ae5302e` = normalization commit, on top of `91ee0a37` = 14/14 CS-level checkpoint.
- Off-box backups: `~/stage3-backups/stage3-src-*.tar.gz` (local) mirrored to the GPU
  rack / read-only host isolated dir `<backup-tree>/` (checksum-verified).
- Build: worktree `~/stage3-build`, build dir `build-s3`; fast gate `test_btx
  --run_test=matmul_v4_rc_stage3_recursive_tests` (expect 18/18).

## DONE + machine-verified (CS-level or measured)
- 52/52 relation-endpoint openings — real, cross-checked vs production fold-root fns.
- 6/6 transport CTL lanes + all coupled/episode kernels → ProgramTable bytecode (bit-identical).
- §4 manifests (Xof/ChaCha/CompleteStream), 6/6, tamper-tested.
- 14/14 role C_rho resolve via ResolveCurrentRCStage3RelationConstraintSystem +
  flip `constraints_resolved` at CS level (CountWitnessViolationsOnH honest->0 / tamper->>0).
- NORMALIZATION (ae5302e): role C_rho verifier-owned preprocessed cols root-equality ->
  OOD-pin (binding unchanged; manifest/fold root still in-circuit). Roles now GENUINELY
  FRI prove+verify: CoupledPermutation 13.18s/2.90s ACCEPT+tamper-reject; CoupledMix
  26.37s/5.53s ACCEPT. `recursive_tests` 18/18.
- Recursion NODE correctness at node shape: builds, fits 2^15 cap (four-slot 17108<32768;
  one-slot 4240), ACCEPT + tamper-reject.
- DEFINITIVE NODE PROVE->VERIFY (measured 2026-07-26): a GPU-accelerated prove emitted a
  COMPLETE AirQuotientProof the REAL unmodified AirQuotientVerify ACCEPTS (prove_ok=1
  verify_ok=1 + independent 18.4s reverify), tampered-fold rejects, wrong-seed rejects.
  Node correctness end-to-end = DONE (measured, not inferred).
- PROVER ECONOMICS (CORRECTED 2026-07-26 -- earlier "~2870x -> seconds" was OVERSTATED,
  twice): the full node prove has THREE co-dominant heavy phases -- Poseidon leaf-commit,
  LDE-NTT, and verifier-AIR composition (the in-AIR 192-query FRI verifier). Errors: (a) the
  isolated commit parity was a FALSE POSITIVE from a lazy-vs-canonical Goldilocks bug in the
  GPU harness (values left in [0,2^64) vs canonical [0,P); diverges on structured constants;
  uniform-random data masked it) -- FOUND + FIXED (canonicalize gl_add/sub/mul, one extra
  subtract); (b) commit is NOT the sole dominant phase. MEASURED: GPU-leaf-commit node prove
  = 48.7min (vs >82min CPU never-finished) -- a real win, NOT seconds. To reach seconds: GPU
  commit + NTT (easy, ~390ms in rowroot_gpu) + composition (compose_parent_gpu) TOGETHER --
  each demonstrated GPU-able in isolation, COMBINED UNMEASURED. So "prover meets budget" is
  PLAUSIBLE but NOT yet demonstrated. LESSON: check every GPU parity on REAL structured data.
- Verifier ~386ms projection (< 900ms relay budget).

## REMAINING to production candidate  [ENG]=engineering / [EXE]=serial-execution+verify
1. FULL 341-NODE TREE round-trip — [EXE mostly + ENG glue]. Run the proven node primitive
   over 256 leaves + 85 internal -> one normalized root -> verify. ENG: tree
   orchestration/walker (wire real children level-to-level), fold the 23 deferred SHA
   stream children into the aggregation, apply the GPU splice tree-wide, confirm
   self-similar shape S* at all depths. Bulk = serial execution of the proven node.
2. g4 CS-DOMAIN CTL BUS — [ENG]. Cross-domain LogUp bus binding companion-CS SHA output
   bytes to the parent decoder's 24 digest bytes so coordinated FS forgery is rejected
   IN parent verification. Decoder already in parent_cs (recursive_parent_air.cpp:3658-3804);
   companion SHA CS at :3934 (bytes currently FREE preprocessed at :3703-3713). Gate wiring:
   complete_sha_fiat_shamir_replay_in_air (:2979) -> ledger fiat_shamir_replay_complete
   (global_soundness_ledger.cpp:615) -> gate.child_fiat_shamir_replay_closed (:679).
3. GATE ROLL-UP -> certified_bits=79 — [EXE/mechanical]. Executable ledger
   (CompositionReadinessGateV1) auto-flips g6 when g0-g5 genuinely close; run on the real
   execution. certified_bits = all_clear ? 79 : 0.
4. REAL-BLOCK END-TO-END — [ENG + EXE]. Build the historical Stage-3 harness
   over a real v4.6 construction block + tx
   -> Stage-3 statement -> prove -> verify. Measure verify < 900ms on the target GPU and
   prover within block interval. NOTHING has run a real block yet.
5. CONSENSUS + MINER INTEGRATION — [ENG]. Wire the GPU prover into the miner
   path and canonical durable proof carriage into validation. The proof may
   become mandatory only at Epoch B, where Profile-1 ExactReplay is also
   required; sole proof authority is a separate Epoch-C change.

## Disclosed assumptions shipping WITH the RC (not blockers)
- M2: Poseidon2 binding (non-standard algebraic hash) — inherent, unremovable by any verification.
- Threat model q* ~ 76 (BTX tensor-mining-anchored proof-grind budget, not Bitcoin 2^94).
- Global bound ~79 (>=64 with margin); >=100-global is a future multi-lane-FRI upgrade.
- FS-instantiation heuristic (one per recursion level) — same class deployed by
  Plonky2/RISC0/Boojum.

## Honest open unknowns
- #1: full-tree end-to-end execution (largest remaining risk; NODE proven prove->verify+tamper
  measured 2026-07-26, but 341-node tree unrun).
- PROVER BUDGET (open): node prove = 48.7min with leaf-commit-only GPU; seconds-scale needs
  all 3 phases (commit + LDE-NTT + verifier-AIR composition) GPU'd TOGETHER on real structured
  data (each GPU-able in isolation, combined UNMEASURED). "prover meets budget" = plausible,
  not demonstrated. 341-node total unmeasured.
- Real-block verify/prove timings (unmeasured; only node/projection so far).
- GPU-parity discipline: a lazy-vs-canonical Goldilocks bug produced a FALSE-POSITIVE
  bit-identical on random data; ALL GPU parity must be re-checked on real structured prove data.

## How to resume
1. `cd ~/stage3-build`; confirm branch `claude/matmul-v4-stage3-recursion-core-af23sj`.
2. Build: `cmake --build build-s3 --target test_btx -j$(nproc)`; run
   `test_btx --run_test=matmul_v4_rc_stage3_recursive_tests` (expect 18/18) to confirm
   the node-level "roles genuinely verify" state.
3. Pick up the 5 remaining items above in order. #2 (g4) and the tree-orchestration glue
   are the next genuine builds; #1 bulk + #3 are execution.
4. GPU harness (on the rack): row-Merkle commit kernel + composed-quotient kernel
   (bit-identical), in `~/gpu-integ/`. The commit is the lever; wire it into AirQuotientProve.
5. Detailed running log: session memory `step5-composition-status.md` +
   `pr89-succinct-proof-is-default.md` (goal), `proof-machine-topology.md` (setup),
   `fvt-terminal-round-budget.md`.
