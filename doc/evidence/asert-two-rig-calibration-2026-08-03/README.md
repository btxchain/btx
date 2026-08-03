# Epoch-A ASERT: two-rig, two-vendor work-ratio calibration

Status: **historical, non-authorizing measurement corpus.** Both halves of the
v3-vs-RC ratio were measured on the *same
silicon*, on *two independent accelerator vendors*, and the previously
unexplained discrepancy is resolved. The raw artifact records the disabled
chain-parameter state and source revision at measurement time. It predates the
strict schema-2 provenance/fallback checks and is intentionally rejected by the
current derivation tool. It is not an activation authorization and must not be
used as exact-final-binary evidence.

## What was blocking this

Two things, both now settled.

**1. Every prior artifact paired a CPU v3 run with a GPU RC run.** That
cross-hardware gap was roughly four orders of magnitude and was, by itself, the
entire spread between candidate answers. Measuring both halves on one rig
removes it. Doing it on two vendors additionally gives the spread of the
*ratio*, which is the quantity that actually matters.

**2. The "unexplained 52% swing" in RC episode time was never variance.**
The 2026-07-30 CUDA campaign reported 21.244 s and the 2026-08-01 campaign
32.273 s on the same hardware class at the same `matmul_dim`. Diffing the two
artifacts field by field shows why:

| | 2026-07-30 | 2026-08-01 |
| --- | ---: | ---: |
| `device_extract_tiles` | 151,499,980,800 | 2,308,571,136,000 |
| `device_gemm_calls` | 28,560 | 13,600 |

ExtractMX work rose **15.2×** while GEMM calls halved. That is an episode-shape
change from a correctness fix, not drift — and the 07-30 directory's own README
already records a CUDA TU fingerprint that does not match tip and points at the
08-01 replacement. **The 21.2 s figure measured less work than consensus
requires and must not be used for calibration.** At the historical measurement
revision the corrected figure was 32.0–32.6 s, and five canary corpora agreed
within 0.6 s.

## Method

v3 mining is a two-stage pipeline: SHA-derived sigma runs for every nonce, the
matmul digest only for nonces passing the pre-hash gate. Three regimes separate
them — `sigma` (ε=18, target 1: gate never passes), `matmul` (ε=255: gate always
passes), `mixed` (ε=18 at live mainnet nBits: the real loop). `R_eff` is taken
as `digest_requests / wall`, a direct count requiring no model. Five independent
100M-attempt samples per rig. RC rates come from the sealed cohort corpora on
the same machines at the same code freeze.

## Result

| | CUDA / `sm_120` | Metal / `m4_class` |
| --- | ---: | ---: |
| `R_eff` (v3 digest trials/s) | 3,795.4 (cv 6.9%) | 710.2 (cv 0.6%) |
| `R_rc` (episodes/s) | 0.031217 | 0.035700 |
| `R_M` (matmul-only) | 7,809.9 | 1,043.9 |
| `A` = 2^ε·p·`R_sigma` | 3,734.8 | 713.0 |
| **γ = R_M / A** | **2.09** | **1.46** |
| regime | sigma-bound | sigma-bound |
| **k = R_eff / R_rc** | **121,581** | **19,892** |
| aggregate raw v3 attempts/s | 215,360,362.49 | 41,251,017.97 |
| **C = raw attempts/s ÷ RC episodes/s** | **6,898,853,852.15** | **1,155,482,264.41** |

Cross-vendor spread **6.11×**; geometric mean **49,178**.

## What the numbers say

**Both rigs are sigma-bound (γ > 1), and they agree on that.** An earlier
CPU-only analysis measured γ ≈ 0.19 and concluded v3 is *matmul*-bound. On
accelerated silicon the matmul is cheap enough that feeding the pre-hash gate
becomes the constraint. The regime is a property of the hardware, not the
protocol — so the harmonic form must be used rather than either limit, and a
CPU-derived calibration does not transfer to the machines that will mine.

**The 6.1× spread has a clean cause.** `R_eff` differs 5.3× between vendors
while `R_rc` differs only 1.14×. v3 mining favours the CUDA rig far more than RC
does. So `k` is not a property of the protocol alone — it depends on the
hardware mix of the network at the fork. That is an irreducible governance
input, not something more measurement can remove.

## Recommendation, and its limits

The loss function is strongly asymmetric: under-loosening is linear in the error
(a factor F too tight ≈ F × 90 s to the first block, then a slow ASERT climb
capped at 1.103× per block by the MTP rule), while over-loosening is
logarithmic (even 10⁶× too loose costs ~4.4 h and a few hundred early blocks).
**Bias high.**

The consensus field is the pre-gate coefficient `C`, not the realized loosen
`k`. The historical arithmetic rule was: aggregate
each provider's raw parent throughput as `sum(attempts) / sum(wall time)`,
multiply by mean RC episode seconds, round half-up to an integer, and choose the
larger required-provider result because under-loosening is the asymmetric
liveness risk. On this historical corpus that yields **`6898853852/1`** from CUDA; the
corresponding Metal result is `1155482264/1`.

The current tool additionally requires schema-2 raw samples from clean binaries
that embed one exact revision/fingerprint, explicit required-backend selection,
and zero CPU fallbacks. It derives RC mean wall time from individual runs rather
than trusting a supplied mean. The release coefficient remains provisional
until both vendors rerun that campaign at the final code freeze.

This selection retains headroom for the fact that neither rig accelerates v3's
sigma stage the way a dedicated miner would (raising `R_sigma` raises `C`). The
MAC-ratio anchor `2^14·1027 = 16,826,368` is **342× above** the geometric mean:
still inside the survivable band and on the safe side, but it would mint a few
hundred blocks early.

What this campaign **cannot** settle, and no further measurement here will:
the network's hardware mix at the fork, and the behaviour of a miner that
accelerates the sigma stage. Both push `C` up, never down, which is the safe
direction. Choosing the provider-selection policy remains a governance
decision informed by these bounds. The arithmetic is now reproducible and must
be rerun against the exact final binaries before the activation-height commit.

## Artifacts

- `raw/two-rig-v3-vs-rc.json` — raw samples and derived values for both rigs.
- A final schema-2 corpus will produce `derived/asert-coefficient.json` with:

  ```bash
  python3 contrib/matmul-v4/derive-epoch-a-asert.py \
    --source-revision <exact-final-40-character-revision> \
    --expected-coefficient <candidate-coefficient>
  ```

The legacy schema-1 file in `raw/` is retained only to document the earlier
measurement and is expected to fail this command.

Machine-class and provider capability data only: no hostname, account name,
filesystem path, device serial, network address, or credential.
