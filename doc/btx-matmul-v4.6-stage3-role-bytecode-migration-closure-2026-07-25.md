# Stage-3 Role-Bytecode Migration Closure (ConstraintRegistryUnavailable)

> **MatMul v4.7 transition status:** historical proof-development
> specification for possible Epochs B–D. It has no Epoch-A authority. Epoch B
> requires a durable proof plus Profile-1 ExactReplay; Profile 2 is reserved
> for Epoch D. See `doc/btx-matmul-v4.7-transition-roadmap.md`.
>
Status: DESIGN SPEC — implementable closure for
`RCStage3RecursiveGapCode::ConstraintRegistryUnavailable`.
Scope: makes `ResolveCurrentRCStage3RelationConstraintSystem` return the
complete proof-only AIR for **every** `RCStage3RelationRole`, and defines the
exact condition under which `kAllRegisteredRoleBytecodeMigrated = true` is
valid. It does NOT close ChildFiatShamirReplayNotClosed,
SelfSimilarFixedPointNotClosed, SoundnessTargetNotMet, or the cross-hash
binding; those remain orthogonal gaps (see §8).

Source files (mirror, read-only study basis):

- `src/matmul/matmul_v4_rc_stage3_constraint_bytecode.{h,cpp}` — SSA bytecode
  (`Opcode::{Current,Next,Constant,Add,Sub,Mul}`, `Program`, `ProgramTable`,
  dual commitment SHA256d + AlgHash, interpreter adapter
  `BuildAirConstraintSystemFromProgramTable`).
- `src/matmul/matmul_v4_rc_stage3_recursive.{h,cpp}` — fail-closed registry
  (`registry:<role>:complete_air_unavailable`), readiness contract
  `cs.n_rows == pin.child_n_rows && cs.n_columns == pin.child_w &&
  !cs.constraints.empty()`.
- `src/matmul/matmul_v4_rc_stage3_role_bytecode.{h,cpp}` — 9 migrated builder
  families (ProgramBuilder idiom).
- `src/matmul/matmul_v4_rc_stage3_hash_air.h` — 32-bit op AIR families
  (Add32/XorRot32/ShaChoice32/ShaMajority32/ShaXor3Transform32; word =
  value + 32 bit columns).
- `src/matmul/matmul_v4_rc_stage3_coupled_air.h` — challenge inputs
  (γ, α ∈ Fp3) of the coupled kernels.
- Caps: `kRCFri3AlgBatchMaxColumns = 2^14`, `kConstraintBytecodeMaxInstructions
  = 2^20`, `kRCFriBlowup = 16`, `kRCFriMaxLdeLog2 = 24`, |Fp| = 2^64−2^32+1
  (Goldilocks), |Fp3| ≈ 2^191.99.

---

## 1. Why the registry fails closed today, and the exact closure condition

`ResolveCurrentRCStage3RelationConstraintSystem(role, pin, out, why)` returns
`registry:<role>:complete_air_unavailable` for all 15 role values because the
14 episode/coupled semantic roles are all `MigrationState::Partial` with
`opaque_callbacks_remain = true` (`CurrentRoleMigrationInventory()`), and the
header hard-pins `kAllRegisteredRoleBytecodeMigrated = false` with
`static_assert(!kAllRegisteredRoleBytecodeMigrated)`.

The opaque residue is exactly three builder families (every "remains opaque"
note in the inventory is an instance of one of them):

| Family | Instances (roles) |
|---|---|
| **H** — 32-bit hash/XOF circuits (SHA-256 compression, SHA256d chaining, ChaCha20 XOF) | 1 (seed/SHA), 3 (scale SHA), 5 (tile SHA), 6 (digest SHA), 7 (bank hash/XOF), 9 (exchange XOF), 12 (ChaCha + scale SHA), 13 (barrier SHA), 14 (digest SHA) |
| **C** — challenge-dependent LogUp / running-product arguments (sampler γ/α lanes, GEMM product, all-tile aggregation, opening/link lanes) | 2, 3, 5, 8, 12, 13 |
| **S** — verifier-owned schedules / wiring (transpose/order, bit-affine permutation, exchange schedule, global mix schedule, T_M/t_fp tables) | 1, 4, 9, 10, 11 |

Closure = express H and C as bytecode gadgets (§3), move S entirely into
verifier-owned **preprocessed columns** (§2.2, zero bytecode), assemble one
unified per-role ProgramTable (§4), replace the fail-closed resolver body
(§5), and flip the constant only under the executable check of §6.

---

## 2. Architecture invariants

### 2.1 One canonical, pin-independent ProgramTable per role

For each of the 14 roles there is exactly one builder

```cpp
[[nodiscard]] bool BuildRCStage3RoleProgramTable(
    RCStage3RelationRole role,
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);   // new, matmul_v4_rc_stage3_role_bytecode.h
```

whose output contains **no pin-, statement-, challenge-, or shard-dependent
constant**. Everything instance-specific enters through preprocessed columns
(§2.2). Consequences:

- `CommitProgramTable` / `CommitProgramTableAlgHash` are compile-time-pinnable
  constants (the registry pins of §6) — the relation is consensus-immutable.
- The same table serves every shard of the role; `pin.child_n_rows` only
  parameterizes the interpreter adapter.
- The AlgHash commitment is replayable by the normalized recursive parent
  (`BuildProgramTableAlgHashPreimage` already exists), which is what the
  self-similar fixed-point closure needs downstream.

### 2.2 Column space convention (witness | parameter)

`ProgramTable::current_width = W_r = W_wit(r) + W_par(r)`; `next_width = W_r`.

- Columns `[0, W_wit)` — prover witness.
- Columns `[W_wit, W_r)` — **parameter columns**, filled by the resolver as
  `AirConstraintSystem::preprocessed` entries with `preprocessed_pin_ood =
  true` (dual-OOD barycentric pinning, O(N) verifier — already implemented in
  `air_quotient.h`). Bytecode reads them with ordinary `Opcode::Current`; the
  opcode set is **unchanged**.

Parameter column classes:

| Class | Content | Derivation (pure function of) |
|---|---|---|
| `SEL_G*` | per-section boolean selectors for vertical stacking (§2.3) | `(role, child_n_rows)` |
| `PG`, `PA`, … | challenge scalars γ, α, … replicated over H (constant columns) | `pin.role_challenges` (§2.4) |
| `KRND` | SHA-256 K_t round-constant word (value + 32 bits = 33 cols) | round index = row position |
| `SCHED*` | transpose/order, bit-affine permutation, exchange and global-mix schedule addresses | `(role, child_n_rows)` shape formulas |
| `TBL*` | T_M table and t_fp = f(γ, T_M) | `(pin.role_challenges, consensus T_M)` |

Rationale for `preprocessed_pin_ood` over root-equality: schedule columns are
Θ(N) values; barycentric dual-OOD pinning costs O(N) Fp3 ops with shared
denominators and adds ≤ 2(N−1)/|Fp3| soundness error per column (§7), versus
per-column LDE+Merkle regeneration which would dominate verification.

### 2.3 Vertical stacking with section selectors

A complete role AIR is the union of its section kernels (e.g. EpisodeDigest =
header-target ∪ root-vector ∪ semantic ∪ PoW ∪ byte-bridge ∪ SHA256d ∪ bus).
Sections share the row domain H; each section's residual is gated:

```
SEL_Gk(row) · R_i(cur, next) = 0        (declared_degree = deg(R_i) + 1)
```

Section row ranges are fixed by a deterministic layout function
`RoleSectionLayout(role, n_rows)` (contiguous ranges, in canonical section
order, capacities from the role's schedule formulas; unused tail rows have all
selectors zero). Selector columns are preprocessed, hence verifier-pinned — a
prover cannot zero a selector to disable a section (same argument as the
Poseidon selector note in `stage3_poseidon_air.h`).

Transition constraints that must not fire across a section boundary are gated
by `SEL_Gk(cur)·SEL_Gk(next)` (degree +2 instead of +1); boundary rows of a
section use dedicated one-row selector columns (`SEL_Gk_FIRST`,
`SEL_Gk_LAST`) instead of AirKind first/last, because AirKind::kFirstRow /
kLastRow address only the global H boundary. Global-H constraints (grand
accumulator init/final) still use AirKind::{kFirstRow,kLastRow}.

### 2.4 Challenge scalars: `ChildPublicInputs::role_challenges`

The resolver's only input besides the role is the pin. Role challenges (γ, α
for LogUp/product lanes) therefore travel **in the pin**, exactly like the
existing non-arithmetized FS scalars (`fri_lambda`, `z1`, …):

```cpp
// air_recurse::ChildPublicInputs (extension, serialized by WriteChildPI,
// absorbed by ComputeRCStage3RecursiveChildPinsCommitment via the pins
// commitment -> fixed_role_commitment -> role seed):
std::vector<Fp3> role_challenges;   // length == kRoleChallengeCount[role]
```

| role_challenges layout | roles |
|---|---|
| `[γ, α]` | 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14 (bus/multiset lanes) |
| `[γ, α, γ_bus, α_bus]` | 1, 6, 7 (separate byte-bus lane pair) |

The resolver fails closed on wrong length. **Honest derivation** of these
scalars (two-epoch: FS over base-column roots, before LogUp columns commit)
is exactly the ChildFiatShamirReplayNotClosed obligation and stays in that
blocker; this closure only makes them *bound* (pins commitment → role seed)
and *consumed* (constant parameter columns). This is the same trust boundary
the existing `fri_lambda`/`z1`/`z2` pins already occupy — no new class of
unverified input is introduced.

---

## 3. Gadget library (exact SSA programs)

Register index = instruction position (SSA). `C(x)` = `Current x`,
`N(x)` = `Next x`, `K(v)` = `Constant v`. All programs end in their unique
result register (interpreter checks last register against zero); the
dead-register rule of `ValidateProgram` is satisfied by construction
(straight-line, every intermediate consumed).

### 3.1 BOOL(b) — booleanity, degree 2, 4 instructions

```
0: C(b)   1: K(1)   2: Sub 0 1   3: Mul 0 2      ; b(b−1)
```

### 3.2 RECOMP32(v, b0..b31) — word recomposition, degree 1, 97 instructions

```
0: C(b0)
for i = 1..31:  K(2^i) ; C(b_i) ; Mul ; Add(acc)
95: C(v)   96: Sub 95 acc                          ; v − Σ 2^i b_i
```

### 3.3 XOR2(out, a, b) — degree 2, 9 instructions

```
0:C(a) 1:C(b) 2:Add 0 1 3:Mul 0 1 4:K(2) 5:Mul 4 3 6:Sub 2 5 7:C(out) 8:Sub 7 6
```

### 3.4 XOR3(out, a, b, c) — degree 3, ~16 instructions

`out − (a+b+c − 2(ab+bc+ca) + 4abc)`. Used per bit for SHA σ/Σ (the three
rotate/shift taps are pure **wiring**: the program reads bit column
`(j + r) mod 32` of the source word for RotateRight(r), and reads a `K(0)`
constant for shifted-out ShiftRight taps — no columns needed for rotation).

### 3.5 CH(out, e, f, g) — degree 2, 9 instructions

`out − (e·f + g − e·g)`   (exact over booleans: e ? f : g).

### 3.6 MAJ(out, a, b, c) — degree 3, ~13 instructions

`out − (ab + bc + ca − 2abc)`.

### 3.7 ADDk32 — k-term 32-bit modular add, degree 1 + BOOL carries

For `x = a1 + … + ak mod 2^32`, carry ∈ [0, k−1], `nc = ⌈log2 k⌉` carry bits:

```
sum(a_i values) − x_value − 2^32·(c0 + 2c1 + …) = 0     ; degree 1
BOOL(c_j) for j < nc                                     ; degree 2
```

k=2: 9 instructions + 1 BOOL. k=5 (SHA T1): ~19 instructions + 3 BOOLs.

### 3.8 SHIFTCOPY(w_i, w_{i+1}) — sliding window, degree 1, 3 instructions

```
0: N(w_i)   1: C(w_{i+1})   2: Sub 0 1        ; AirKind gated by SEL·SEL_next
```

### 3.9 LOGUP-LANE(φ, key, val, m; PG, PA) — degree 3 (4 gated), 13 instructions

Cross-multiplied LogUp step (transition):

```
0:N(φ) 1:C(φ) 2:Sub 0 1 3:C(PG) 4:C(key) 5:C(PA) 6:C(val) 7:Mul 5 6
8:Add 4 7 9:Sub 3 8 10:Mul 2 9 11:C(m) 12:Sub 10 11
;  (φ' − φ)·(γ − (key + α·val)) − m  = 0
```

Boundary: section-first `φ = 0` (1 instruction: `C(φ)`, gated), section-last
`φ − EXPORT = 0` (3 instructions) where EXPORT is the role's CTL export
column (bound to the CTL terminal by the existing
`ValidateRCStage3RecursiveCtlBinding` / unified-root dual-alpha links).

### 3.10 PROD-LANE(Φ, key, val; PG, PA) — degree 3 (4 gated), 13 instructions

```
Φ' − Φ·(γ + key + α·val) = 0
```

Same boundary treatment (init Φ = 1, final Φ = EXPORT).

### 3.11 SHA-256 compression table (SHA256CMP) — one section, row = one round

Layout (per row), all words in `stage3_hash_air` convention value+32 bits:

| block | words | columns |
|---|---|---|
| state a..h | 8 | 264 |
| schedule window w[0..15] (sliding) | 16 | 528 |
| temps: s0, s1, S0, S1, ch, maj, T1, T2 | 8 | 264 |
| carries (T1 5-term: 3; T2 2-term: 1; w' 4-term: 2; a',e' 2-term: 2) | — | 8 |
| **witness total** | | **1064** |
| parameters: KRND (33), SEL_SHA, SEL_SHA_FIRST, SEL_SHA_LAST, SEL_BLK_FIRST, SEL_BLK_LAST | | 38 |

Programs (all SEL-gated, so +1 degree over the raw gadget):

- BOOL × 1064-ish bit/carry columns — deg 3 gated.
- RECOMP32 × 32 words — deg 2 gated.
- σ0(w[1]), σ1(w[14]) → s0, s1: XOR3 per bit with Rot/Shift wiring, 64
  programs, deg 4 gated.
- Σ0(a), Σ1(e) → S0, S1: XOR3 × 64, deg 4 gated.
- CH(e,f,g) → ch: 32 programs deg 3 gated; MAJ(a,b,c) → maj: 32 deg 4 gated.
- T1 = h+S1+ch+KRND+w[0] (ADD5), T2 = S0+maj (ADD2): 2 programs deg 2 gated.
- Round transition (SEL·SEL_next gated, deg 3): a' = T1+T2 (ADD2 on next-row
  a value), e' = d+T1, {b,c,d,f,g,h}' = {a,b,c,e,f,g} (copy, 3-instr), plus
  schedule shift w[i]' = w[i+1] × 15 and w[15]' = σ1+w[9]+σ0+w[1-tap]+w[0-tap]
  (ADD4).
- Block boundary (SEL_BLK_*): feed-forward `state' = state + digest_in`
  (ADD2 lanes) and IV/init binding to the byte-bus lanes.

Counts: ~1,230 programs, worst program ≤ ~100 instructions, max declared
degree 4. Rows: 64 per compression; SHA256d = 2 chained compressions (+1 for
the second-block constant padding of the 32-byte midstate).

### 3.12 ChaCha20 table (CHACHA) — row = one double-round

16 state words (528 cols) + 16 QR temp words (528) + carries (~16) + input
binding. XOR-ROTL(16,12,8,7) are XOR2-with-wiring; adds are ADD2. ~1,090
witness columns, ~1,100 programs, max degree 3 gated, 10 rows per block +
final `out = state + input` add row.

### 3.13 Bus lanes (BUS)

Every H-section's byte I/O (preimage bytes in, digest bytes out) and every
S-schedule copy is a pair of LOGUP-LANE / PROD-LANE multiset arguments over
`key = row-tag (SCHED* preprocessed)`, `val = byte/word column`, with the
already-migrated byte-bridge sections (endpoint-19/23/24/28/29 bridges)
supplying the range-proved byte columns. This is the same discipline the
migrated bridges already commit to; the lanes just replace the opaque
"aggregation/link/product" callbacks.

---

## 4. Per-role complete ProgramTable structure

Notation: `G0..Gk` = ordinal-contiguous constraint groups (ordinals are
assigned in listed order; `constraint_ordinal` = position in
`ProgramTable::programs`, enforced by `ValidateProgramTable`). "kept" =
already-migrated group from `role_bytecode.cpp` / local-kernel builders,
re-emitted at its new column offsets and ordinals (ProgramBuilder idiom
unchanged). Width = W_wit + W_par (worst-case layout targets; final constants
are fixed in code and frozen by the §6 pins). All ≤ 2^14 cap with ≥ 8×
headroom in the two SHA-heavy roles.

| # | Role | Groups (order) | ~W_wit | ~W_par | ~programs | max gated deg |
|---|------|----------------|-------|-------|-----------|---------------|
| 1 | EpisodeDeterministicBuilder | G0 dequant (kept, 5) · G1 semantic (kept, 3) · G2 CHACHA seed-XOF (§3.12) · G3 SHA256CMP seed-SHA (§3.11) · G4 BUS xof→mantissa/scale (4 lanes) | 2200 | 90 | 2400 | 4 |
| 2 | EpisodeGemm | G0 endpoint gf=a·b (kept) · G1 semantic (kept, 3) · G2 product: acc' = acc + a·b (deg 3 gated) + operand-opening LOGUP lanes (2) + boundary | 20 | 12 | 20 | 4 |
| 3 | EpisodeExtract | G0 197-col mix (kept, 201) · G1 semantic (kept, 3) · G2 sampler lanes: (φ'−φ)(γ−t)−m, ψ-lane with α, t_fp = TBL param col, boundary · G3 SHA256CMP scale-SHA · G4 all-tile PROD-LANE | 1300 | 80 | 1450 | 4 |
| 4 | EpisodeWiring | G0 copy kernel (kept) · G1 semantic (kept, 3) · G2 transpose/order: SCHED addr params + 2 LOGUP multiset lanes (val + α·addr) | 20 | 14 | 18 | 4 |
| 5 | EpisodeTileTree | G0 semantic (kept, 3) · G1 signed-byte bridge (kept, 15-col) · G2 SHA256CMP tile hash · G3 tree chaining BUS (digest-out lane ↔ parent-preimage lane) + root boundary | 1100 | 60 | 1300 | 4 |
| 6 | EpisodeDigest | G0 header-target (kept, 1) · G1 root-vector (kept, 4) · G2 semantic (kept, 3) · G3 PoW borrow-chain (kept, 14) · G4 preimage byte bridge (kept, 13-col) · G5 SHA256CMP ×2 (SHA256d) · G6 BUS preimage↔root-vector exports (γ_bus/α_bus) | 1150 | 100 | 1350 | 4 |
| 7 | CoupledBank | G0 dequant (kept, 5) · G1 byte bridge (kept, 10) · G2 bank kernel (kept, 10) · G3 CHACHA bank-seed XOF · G4 SHA256CMP page inclusion + BUS lanes | 2250 | 100 | 2450 | 4 |
| 8 | CoupledGemm | G0 accumulation kernel (kept, 6) · G1 product/opening lanes (as role 2 G2) | 20 | 12 | 20 | 4 |
| 9 | CoupledExchange | G0 fixed-copy kernel (kept) · G1 CHACHA exchange XOF · G2 SCHED exchange schedule + 2 LOGUP lanes | 1120 | 70 | 1160 | 4 |
| 10 | CoupledPermutation | G0 mapped-copy kernel (kept) · G1 bit-affine SCHED addr params + 2 LOGUP multiset lanes | 20 | 14 | 18 | 4 |
| 11 | CoupledMix | G0 288 limb/range (kept) · G1 global mix SCHED params + LOGUP lanes per mix lane | 310 | 40 | 310 | 4 |
| 12 | CoupledExtract | G0 197-col mix (kept, 201) · G1 sampler lanes (as role 3 G2) · G2 CHACHA + SHA256CMP scale · G3 PROD-LANE | 2350 | 90 | 2550 | 4 |
| 13 | CoupledBarrier | G0 root-vector (kept, 4) · G1 SHA256CMP ×2 barrier SHA256d · G2 link BUS lanes | 1150 | 80 | 1300 | 4 |
| 14 | CoupledDigest | G0 root-vector (kept, 4) · G1 SHA256CMP ×2 digest SHA256d · G2 preimage BUS lanes | 1150 | 80 | 1300 | 4 |

(CompositionLink = 32 is an aggregation relation, tracked separately per the
inventory comment; it is not part of the 14-role gate and keeps its own
migrated table under the unified-root builder.)

Every group re-uses the exact `ProgramBuilder` emission idiom of
`role_bytecode.cpp` (role committed in each `Program`, ordinal = table
position, `declared_degree` = syntactic degree, widths uniform per table so
`ValidateProgramTable` passes).

Capacity checks (hard, at build time of each table):
`programs.size() ≤ 2^20` ✓ (max ~2,550); per-program instructions ≤ 2^20 ✓
(max ~600, XOR3-recomposition worst case); width ≤ `kRCFri3AlgBatchMaxColumns
− 1` ✓ (max ~2,450 vs 16,383).

Degree/LDE budget: gated degree ≤ 4 ⇒ `quotient_len ≈ 4(N−1)` ⇒ per-shard
constraint `4(N−1) ≤ 2^(kRCFriMaxLdeLog2 − log2 blowup) = 2^20` ⇒
`N ≤ 2^18` rows per shard, enforced at resolve time (existing
BackendLdeCapExceeded path). SHA sections at 64 rows/compression give
≥ 4,096 compressions per shard — the aggregation schedule's arity-4 tree
absorbs larger hash manifests across shards.

---

## 5. The resolver

Replace the fail-closed body in `matmul_v4_rc_stage3_recursive.cpp`:

```cpp
bool ResolveCurrentRCStage3RelationConstraintSystem(
    RCStage3RelationRole role,
    const ChildPI& pin,
    air_quotient::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    out = {};
    if (!IsKnownRole(role)) return Fail(why, "registry:unknown_role");
    if (role == RCStage3RelationRole::CompositionLink) {
        return Fail(why, "registry:composition_link_separate");
    }
    // 1. Canonical pin-independent table.
    constraint_bytecode::ProgramTable table;
    if (!BuildRCStage3RoleProgramTable(role, table, why)) return false;

    // 2. Registry pinning: dual commitment must equal the compiled-in pins.
    //    (Fails closed on any drift between builder code and pins.)
    const RCStage3RoleTablePin& tp = RCStage3RoleTablePinFor(role);
    if (constraint_bytecode::CommitProgramTable(table) != tp.sha256d ||
        !(constraint_bytecode::CommitProgramTableAlgHash(table) == tp.alg_hash)) {
        return Fail(why, "registry:table_commitment_mismatch");
    }

    // 3. Shape contract required by AssessRCStage3RecursiveReadiness.
    if (table.current_width != pin.child_w) {
        return Fail(why, "registry:width_mismatch");
    }
    if (pin.child_n_rows < 2 ||
        (pin.child_n_rows & (pin.child_n_rows - 1U)) != 0 ||
        pin.child_n_rows > kRCStage3RoleMaxShardRows /* 2^18, §4 */) {
        return Fail(why, "registry:rows");
    }

    // 4. Interpreter adapter: bytecode -> callback CS (thin, exact).
    if (!constraint_bytecode::BuildAirConstraintSystemFromProgramTable(
            table, pin.child_n_rows, out, why)) {
        return false;
    }

    // 5. Parameter columns (pure function of (role, pin)): selectors,
    //    challenge constants, K_t, schedules, T_M/t_fp.
    if (!AttachRCStage3RoleParameterColumns(role, pin, out, why)) {
        out = {};
        return false;
    }
    return true;
}
```

`AttachRCStage3RoleParameterColumns` (new, `role_bytecode.cpp`):

```cpp
bool AttachRCStage3RoleParameterColumns(
    RCStage3RelationRole role, const ChildPI& pin,
    air_quotient::AirConstraintSystem<Fp3>& cs, std::string* why)
{
    if (pin.role_challenges.size() != kRoleChallengeCount(role)) {
        return Fail(why, "registry:role_challenge_arity");
    }
    const RoleLayout L = RoleSectionLayout(role, cs.n_rows); // deterministic
    // SEL_G* selectors, SEL_*_FIRST/LAST one-hot rows.
    for (const Section& s : L.sections) {
        cs.preprocessed.emplace_back(s.sel_col, SelectorColumn(s, cs.n_rows));
        ... first/last one-hot columns ...
    }
    // Challenge constant columns: column j filled with role_challenges[k].
    for (uint32_t k = 0; k < pin.role_challenges.size(); ++k) {
        cs.preprocessed.emplace_back(
            L.challenge_col(k),
            std::vector<Fp3>(cs.n_rows, pin.role_challenges[k]));
    }
    // KRND (SHA roles): 33 columns of K_{t mod 64} words/bits.
    // SCHED*: transpose/bit-affine/exchange/mix address columns from the
    //         shape formulas (functions of role and n_rows only).
    // TBL*:  T_M and t_fp(gamma, T_M) for sampler roles.
    ...
    cs.preprocessed_pin_ood = true;   // dual-OOD barycentric pinning
    return true;
}
```

Properties:

- **Fail-closed preserved everywhere**: unknown role, challenge arity, width,
  row bound, commitment drift, adapter validation — each returns false with a
  typed `registry:*` reason; there is no permissive path.
- The readiness contract (`cs.n_rows == pin.child_n_rows`, `cs.n_columns ==
  pin.child_w`, non-empty constraints) is met by construction, so
  `AssessRCStage3RecursiveReadiness` sets `constraints_resolved = true` and
  the ConstraintRegistryUnavailable gap is no longer emitted.
- The serialized `ChildPublicInputs::child_constraints` stays empty on the
  wire (unchanged rule); callbacks are reconstructed locally from
  `(registry_version, role)`, now via the committed table instead of ad-hoc
  builders. Bump `kRCStage3ConstraintRegistryVersion` 2 → 3 (pin layout
  changed by `role_challenges`).

---

## 6. Exact validity condition for `kAllRegisteredRoleBytecodeMigrated = true`

The constant may flip only in the commit that lands ALL of the following,
and the flip is *checked by executable code*, not by convention:

### 6.1 Compiled-in dual pins (consensus freeze)

```cpp
// constraint_bytecode.h
struct RCStage3RoleTablePin {
    RCStage3RelationRole role;
    uint256 sha256d;                 // CommitProgramTable
    alg_hash::Digest alg_hash;       // CommitProgramTableAlgHash
};
extern const std::array<RCStage3RoleTablePin, 14> kRCStage3RoleTablePins;
static_assert(kRCStage3RoleTablePins.size() == 14);
```

All 28 digests non-null, in canonical role order (1..6, 16..23).

### 6.2 Executable migration proof

```cpp
[[nodiscard]] bool VerifyAllRegisteredRoleBytecodeMigrated(std::string* why);
```

returns true iff, for **each** of the 14 roles:

1. `BuildRCStage3RoleProgramTable(role, t)` succeeds and
   `ValidateProgramTable(t)` holds (this transitively enforces SSA
   well-formedness, dead-register-freedom, exact declared degrees, ordinal
   contiguity, uniform widths, instruction caps).
2. `CommitProgramTable(t) == pin.sha256d` and
   `CommitProgramTableAlgHash(t) == pin.alg_hash`.
3. `CurrentRoleMigrationInventory()[role]` is
   `{MigrationState::Complete, group_count(role), opaque_callbacks_remain=false}`
   and `group_count(role)` equals the number of §4 groups actually emitted.
4. **Differential equivalence** against the retained legacy builders (moved to
   a test-only target, never linked into consensus code): constraint count,
   `AirKind`, and `alg_degree` match 1:1 in canonical order, and for 64
   uniformly random `(current, next) ∈ Fp3^{2W}` samples plus the structured
   boundary vectors, `EvaluateProgram` equals the legacy callback on every
   constraint. Error bound: two distinct ≤-degree-8 polynomials agree at a
   random point w.p. ≤ 8/|Fp3| ≈ 2^-189; union over ≤ 2^12 constraints × 14
   roles × 64 trials ⇒ false-accept ≤ 2^-165.
5. **Resolver smoke**: `ResolveCurrentRCStage3RelationConstraintSystem(role,
   synthetic_pin(role))` (schedule-shaped pin with dummy challenges of correct
   arity) returns a CS with `n_columns == t.current_width`,
   `constraints.size() == t.programs.size()`, and every preprocessed column
   index < `n_columns`.
6. **Static opacity sweep** (CI lint, part of the check's definition): no
   `AirConstraint<…>::eval = [` assignment exists outside (a)
   `constraint_bytecode.cpp`'s single interpreter adapter and (b) test/legacy-
   reference targets. (Mirror-tree baseline to burn down: 44 sites in
   `stage3_v6_fs.cpp`, 26 in `air_recurse.cpp`, 22 in `stage3_v5_v6_bus.cpp`,
   14 in `stage3_verifier_air.cpp`, etc. — every consensus-reachable one
   is replaced by a §3/§4 table or moved behind the adapter.)

### 6.3 Header flip

```cpp
inline constexpr bool kAllRegisteredRoleBytecodeMigrated = true;
static_assert(kAllRegisteredRoleBytecodeMigrated);   // was static_assert(!...)
```

plus a mandatory unit test `stage3_role_bytecode_migration_tests.cpp` that
calls `VerifyAllRegisteredRoleBytecodeMigrated` and fails the suite otherwise,
and a debug-build assertion of the same predicate at first registry use.
`kRCStage3RecursiveAggregationReady` stays false — closing this blocker does
not enable consensus authority (the other five gaps still gate readiness).

---

## 7. Bit accounting (delta of this closure only)

Target: 100 bits (`kRCStage3RecursiveTargetSoundnessBits`). |Fp3| =
(2^64 − 2^32 + 1)^3 ⇒ log2|Fp3| ≈ 191.99.

| Term | Bound | Bits |
|---|---|---|
| Bytecode interpretation (adapter, `EvaluateProgram`) | exact — identical polynomial identities | 0 loss |
| Dual-OOD preprocessed pinning, per column | ≤ 2(N−1)/\|Fp3\| ≤ 2·2^18/2^192 | ≤ 2^-173 |
| … union over ≤ 2^9 parameter columns × 14 roles × 4 children | | ≤ 2^-160 |
| LogUp/product lane (per lane, lane length ≤ N ≤ 2^18) | ≤ N·d/\|Fp3\| | ≤ 2^-171 |
| … union over ≤ 2^6 lanes | | ≤ 2^-165 |
| Differential-equivalence false accept (one-time, dev-side gate) | §6.2(4) | ≤ 2^-165 |
| Degree bump (gating +1/+2, challenge-as-column +1) | affects quotient_len, not FRI rate/queries — enforced `4(N−1) ≤ 2^20` | 0 loss |
| **Total closure-added soundness error** | | **< 2^-159** |

Unchanged by this closure (still open, tracked by their own gap codes):
single-lane FRI 92.6 < 100 bits (SoundnessTargetNotMet), child FS transcript
replay, self-similar fixed point, SHA↔AlgHash first-collision hybrid
(`cross_hash_collision_binding_proved` stays false in
`ProgramTableCommitmentPair` — the dual pins of §6.1 deliberately pin *both*
digests so the hybrid theorem can later bind them without re-freezing tables).

Prover-side cost sanity (not consensus): worst role width ~2.5k columns ×
N ≤ 2^18 at blowup 16 stays under the 2^24 LDE cap; verification remains
O(Q·polylog) per shard — the ms-scale verify budget is untouched; the ~41 s
proving cost grows roughly with total witness area (< 2× the current
episode-scale instantiation for the SHA-heavy roles).

## 8. Explicit non-goals / residuals

1. `role_challenges` honest FS derivation (two-epoch, base-roots-only
   preimage) — ChildFiatShamirReplayNotClosed closure; this spec fixes their
   *binding* (pins commitment → `fixed_role_commitment` → role seed) and
   *arity* only.
2. In-AIR replay of `CommitProgramTableAlgHash` by the recursive parent
   (fixed-point closure) — enabled by, not part of, this migration
   (preimage builder already exported).
3. FRI soundness uplift to ≥ 100 bits, 900 ms production measurement,
   authority gates (`kRCStage3RecursiveAggregationReady`) — unchanged.
4. CompositionLink (role 32) table — owned by the unified-root builder,
   outside the 14-role gate by the inventory's own definition.
