# SMILE 2021/564 Working Mirror

Date: 2026-03-21

Primary source:
- local PDF: `/Users/admin/Downloads/2021-564.pdf`
- local extracted text mirror: `doc/research/smile-2021-564.txt`
- upstream paper: <https://eprint.iacr.org/2021/564.pdf>

Purpose:
- maintain a local, token-cheap working mirror for the BTX SMILE rewrite;
- keep the exact figure / equation shape that the code is supposed to match;
- record the current in-repo code surface that corresponds to each paper object.

This is not a full paper transcript. It is the minimal local mirror needed for
the BTX production rewrite.

## Figure map

### Figure 7: main protocol

Working summary:
- commit `v_1 .. v_m`, `w_0 = A * y_0`, and `g` before the final challenge;
- derive `c_0` from the round-1 transcript;
- compute `z_0 = y_0 + c_0 * s`;
- build `P_1 = NTT(-c_0 * pk_1 | ... | -c_0 * pk_n)`;
- set `x_1 = NTT(w_0 - A * z_0)`;
- run `SM_j` recursion for `j = 1 .. m-1`;
- derive `gamma_m`, compute the linear-final-layer object from Eq. (23), then
  `y_m` from Eq. (24);
- derive `alpha_0 .. alpha_m`, build `psi_sm`, `omega_sm`, `psi_bin`,
  `omega_bin` from Eqs. (28)-(29), commit `t_{k+2m+1}`, then derive `c`;
- compute `z = y + c * r`, apply rejection sampling, and verify with Fig. 9.

Current BTX code surface:
- membership prover / verifier:
  - `src/shielded/smile2/membership.cpp`
  - `src/shielded/smile2/membership.h`
- CT wrapper and direct-spend surface:
  - `src/shielded/smile2/ct_proof.cpp`
  - `src/shielded/v2_proof.cpp`

### Figure 8: recursive sub-protocol `SM_j`

Working summary:
- `j = 1`: challenge `gamma_1` is in `M_q^(k*l)`;
- `j >= 2`: challenge `gamma_j` is in `M_q^l`;
- `P_{j+1}` is the challenge-compressed matrix from Eq. (21);
- `x_{j+1} = P_{j+1}(v_{j+1} \otimes ... \otimes v_m)`;
- `y_1 = v_1 o x_2 - sum_i x_{1,i} o gamma_{1,i}`;
- `y_j = v_j o x_{j+1} - x_j o gamma_j` for `j >= 2`;
- each `x_{j+1}` is committed and becomes public proof state.

Current BTX code surface:
- recursion helpers:
  - `CompressFirstRoundMatrix(...)`
  - `CompressRecursionMatrix(...)`
  - `EvaluateCompressedMatrix(...)`
  - `DeriveSlotChallenges(...)`
  - `DeriveRecursionChallenge(...)`
- all currently live in `src/shielded/smile2/membership.cpp`

### Figure 9: verifier equations

Working summary:
- Lines 01-02: norm checks on `z_0`, `z`
- Line 03: `B_0 * z = w + c * t_0`
- Line 04: adjust `(t_{m+1}, ..., t_{m+k}) := (t_{m+1}, ..., t_{m+k}) - A * z_0`
- Line 05: `f_j = <b_j, z> - c * t_j`
- Lines 06-09: derive `gamma` values and `x_{m+1}` from Eq. (23)
- Lines 10-12:
  - `F_1 = f_1 * f_{m+k+1} + c * sum_i gamma_{1,i} * f_{m+i}`
  - `F_j = f_j * f_{m+k+j} + c * gamma_j * f_{m+k+j-1}` for `2 <= j <= m-1`
  - `F_m = c - sum_i x_{m+1,i} * f_i + gamma_{m,1} * f_{k+2m-1} - e_1 * sum_i gamma_{m,i+1}`
- Line 13:
  - `alpha_0 * (sum_j F_j - c * f_{k+2m} - c^2 * h) + sum_i alpha_i * (f_i^2 + c * f_i) + f_{k+2m+1} = omega`
- Lines 14-15: first `d/l` coefficients of `h` are zero.

Current BTX code surface:
- `VerifyMembership(...)` in `src/shielded/smile2/membership.cpp`

### Figure 10: rejection sampling

Working summary:
- `Rej0(z, v, s)`:
  - accept with probability `M^-1 * exp((-2<z,v> + ||v||^2) / (2 s^2))`
- `Rej1(z, v, s)`:
  - if `<z,v> < 0`, reject;
  - else accept with the same probability term.
- The paper uses `Rej0` for `z_0` and `Rej1` for `z`.

Current BTX code surface:
- rejection helpers in:
  - `src/shielded/smile2/membership.cpp`
  - `src/shielded/smile2/ct_proof.cpp`

## Equation map

### Eq. (21): recursive matrix compression

Meaning:
- `P_{j+1}` is formed by stacking challenge-weighted transposes of the `l`
  block-columns of `P_j`.

BTX mapping:
- `CompressFirstRoundMatrix(...)`
- `CompressRecursionMatrix(...)`

### Eq. (22): recursion witness relation

Meaning:
- `x_{j+1}` is the compressed witness state;
- `y_j` is the linear residual proving the compressed state matches the
  selector decomposition.

BTX mapping:
- `y_1` and `y_j` construction inside `ProveMembership(...)`

### Eq. (23): final linear matrix

Meaning:
- `tilde(P)_m` has:
  - a top block row `[0 ... 0 P_m]`
  - diagonal `B` blocks beneath it
- therefore:
  - for `i < m`, `x_{m+1,i} = B^T * gamma_{m,i+1}`
  - for `i = m`, `x_{m+1,m} = P_m^T * gamma_{m,1} + B^T * gamma_{m,m+1}`
- because `B` has a first row of ones and zero elsewhere, `B^T * gamma`
  becomes the repeated first-slot image.

BTX mapping:
- `ComputeFinalPublicXValues(...)` in `src/shielded/smile2/membership.cpp`

### Eq. (24): final linear residual

Meaning:
- `y_m = sum_i v_i o x_{m+1,i} - x_m o gamma_{m,1} - e_1 o sum_i gamma_{m,i+1}`

BTX mapping:
- `ComputeFinalMembershipDelta(...)` in `src/shielded/smile2/membership.cpp`

### Eq. (27): `psi_m`

Meaning:
- `psi_m = -sum_i x_{m+1,i} * <b_i, y> + gamma_{m,1} * <b_{k+2m-1}, y> - e_1 * sum_i gamma_{m,i+1}`

BTX mapping:
- the `psi_m` block in `ProveMembership(...)`

### Eqs. (28)-(30): garbage / binary aggregation

Meaning:
- `omega_sm = sum_{i=1}^{m-1} omega_i`
- `psi_sm = sum_{i=1}^{m} psi_i - <b_{k+2m}, y>`
- `omega_bin = sum_i alpha_i * <b_i, y>^2`
- `psi_bin = sum_i alpha_i * <b_i, y> * (1 - 2 v_i)`
- final verifier line uses the combined `alpha_0` / `alpha_i` relation.

BTX mapping:
- `psi_sm`, `omega_sm`, `psi_bin`, `omega_bin` construction inside
  `ProveMembership(...)`
- Fig. 9 line-13 recombination in `VerifyMembership(...)`

### Eq. (31): public first-round matrix

Meaning:
- `P_1 = NTT(-c_0 * pk_1 | ... | -c_0 * pk_n)`
- `x_1 = NTT(w_0 - A * z_0)`

BTX mapping:
- `p1_rows`
- `x1_rows`
- both currently built in `ProveMembership(...)` and reconstructed in
  `VerifyMembership(...)`

### Eq. (39): first Fiat-Shamir `c_0` surface

Meaning:
- `c_0` is derived from the first commitment surface
  `(~t_0, t_1 .. t_{m+k}, t_{k+2m}, w~, m)`;
- the `w~ = B_0 * y` rows and the recursion depth `m` are part of the
  transcript before `c_0` is sampled.

BTX mapping:
- `ComputeB0Response(...)`
- `AppendUint32(...)`
- first-round transcript construction in `ProveMembership(...)`
- matching reconstruction in `VerifyMembership(...)`

## Current rewrite annotations

### Membership rewrite

Open code target:
- `src/shielded/smile2/membership.cpp`

What the live rewrite is trying to enforce:
- dense ternary `c` / `c_0` challenge distribution `C`
- Eq. (39) first-round transcript binding of `w~` and `m`
- Eq. (31) sign-consistent `P_1`
- Eq. (21) full `gamma^T * P` row compression over all row slots
- committed `x_2 .. x_m` recursion state
- Eq. (23) repeated-first-slot `B^T * gamma` image
- Fig. 9 line-13 aggregation shape
- removal of any deanonymizing public-key unique-match recovery on the `m > 1`
  path

Focused local regression probes:
- `src/test/smile2_membership_tests.cpp`
  - `p3_g4_medium_set`
  - `p3_g7c_medium_set_wrong_key_rejected`
  - `p3_g7d_medium_set_wrong_index_rejected`

Current result:
- the standalone `m > 1` membership path now passes the `N=1024` honest probe
  and rejects both medium-set forged-key probes above on the rewritten
  Figure-7/8/9 path;
- BTX's live direct-spend path now defaults to `RING_SIZE = 8` while
  `NUM_NTT_SLOTS = 32`, so wallet-built direct sends still exercise the
  single-round `m = 1` surface today; that path now uses the rewritten hidden
  membership object too.

Historical correction on 2026-03-22:
- the older March 20 branch-local note that treated the CT-side public-coin /
  Figure 17 rewrite as the remaining `DIRECT_SMILE` production blocker became
  stale after the PR `#108` / `#110` / `#111` proof-core landings;
- the live reset-chain `DIRECT_SMILE` launch surface now includes the
  weak-opening `omega`, framework `framework_omega`, and combined coin-opening
  verifier work that those older notes were waiting on;
- the remaining open work on
  `codex/smile-v2-account-registry-design` is registry-redesign activation
  work, not completion of the base `DIRECT_SMILE` launch path.

### CT rewrite

Open code target:
- `src/shielded/smile2/ct_proof.cpp`

What still has to match the paper:
- Appendix E public-account / public-coin statement
- authenticated input/output coin openings `coin_r`
- final garbage relation over the public coin commitments rather than a
  verifier-recovered hidden index
- For BTX's genesis-reset launch, these items should be implemented as a clean
  final proof-object / transcript design even if that requires replacing the
  current `SmileCTProof` wire format.

Concrete Appendix E checkpoints pulled into the local mirror from the paper:
- Fig. 16 line 26:
  - `g0 = g0 + <b05, y0>`
- Fig. 17 lines 14-15:
  - `f~00 = (...) + B00 z~ - sum_i beta_i * t~(out)_{i,0} * c`
  - `f10 = f7+m+n+κ+1 + <b01, z~> * c + <b02, z~> - ...`
- Fig. 17 line 24:
  - `g0 ?= g + (h - h2 c^2) c^2 + f5 + f6 c + f7 c^2`

Current BTX mapping:
- `src/shielded/smile2/ct_proof.cpp` now reconstructs the temporary
  placeholder `matched_indices` on the combined public-account tuple rows
  rather than on `pk` alone.
- The current CT rewrite also moved the first-round aux / `w0` surface onto
  the same combined tuple-account rows (`KEY_ROWS + 1`, including the
  `t_msg` row) instead of carrying raw key-only `A*y0` rows in the proof and
  aux commitment.
- The live `SmileCTProof` object now also carries the explicit key-surface
  `key_w0 = A*y0` rows again, and the prover / verifier rebuild the combined
  tuple-account `w0` rows from `key_w0 + input_tuples` instead of serializing
  those mixed rows directly in the proof object.
- Historical note: the paragraph that previously called Figure 17 step 24 and
  the hidden public-coin opening checks the remaining production blocker was
  accurate for the March 20 branch state but stale after PR `#108` / `#110` /
  `#111`. The live reset-chain verifier now ships the production
  direct-spend Figure 17 path; current branch-local blockers are the
  account-registry consumed-leaf relation for non-SMILE paths and the minimal
  output activation contradiction.

## Maintenance rule

When the BTX rewrite learns something concrete from the paper, record it here
first and then cite this mirror from:
- `doc/btx-smile-v2-genesis-readiness-tracker-2026-03-20.md`
- `doc/btx-shielded-production-status-2026-03-20.md`
- any proof-header comments that describe the remaining gap.
