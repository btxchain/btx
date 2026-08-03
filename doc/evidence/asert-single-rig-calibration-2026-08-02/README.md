# Epoch-A ASERT: single-rig v3-vs-RC work ratio

Status: **historical first same-silicon measurement of the Epoch-A work
ratio.** At measurement time nothing was installed and the RC schedule was
neutral/disabled. The current release candidate stages a static height and
coefficient, but this artifact does not authorize them.

## Why this exists

Every prior work-ratio artifact in this tree paired a **CPU** v3 measurement
with a **GPU** RC measurement. That cross-hardware gap is roughly four orders of
magnitude and was, by itself, the entire spread between the candidate answers.
It is also the one term no amount of re-derivation could fix. This campaign
measures both sides of the ratio on **one rig, at one code freeze, in one
afternoon**, which removes that term.

Freeze: `c7e7711e655859d5b17ab3c79666399df07f7ef2`, build-relevant fingerprint
`174436c75da89fb8b7ee6a2c1a9045ff32cbeeb623f72defce82336b24b2be62`. The RC side
is the exact-freeze CUDA corpus in
`../multi-gpu-profile1-goldens-cuda-2026-08-02-freeze/`, so both halves are the
same binary tree on the same Blackwell-class `sm_120` device.

## Method

v3 mining is a two-stage pipeline: SHA-derived sigma runs for every nonce, and
the matmul digest runs only for nonces that pass the pre-hash gate
(`sigma <= target << epsilon`, epsilon = 18 on mainnet). Three regimes separate
the stages:

| mode | epsilon | target | measures |
| --- | --- | --- | --- |
| `sigma` | 18 | 1 | SHA grind only — the gate never passes, `digest_requests` = 0 |
| `matmul` | 255 | 1 | every attempt runs a digest — `R_M` |
| `mixed` | 18 | live mainnet nBits | the real loop — `R_eff` directly |

`R_eff` is taken as `digest_requests / wall`, which is a direct count and needs
no model. Five independent 100M-attempt samples.

## Result

```
R_eff  = 3,795 v3 digest trials/s   (sd 263, cv 6.9%, n=5)
R_rc   = 0.031074 episodes/s        (8 episodes, mean 32.1816 s)

k = R_eff / R_rc = 122,140          (105,482 .. 128,351 across samples)
```

The `mixed` digest counts (1,703–1,803 per 100M attempts) match the predicted
`100e6 × 2^18 × p` = 1,728 within Poisson noise, so the two-stage model is
validated end to end rather than assumed.

## The regime is sigma-bound, which contradicts the CPU-derived analysis

```
A     = 2^eps * p * R_sigma = 3,735 eligible nonces/s
R_M   = 7,810 digests/s
gamma = R_M / A = 2.09     ->  SIGMA-bound
```

An earlier CPU-only analysis measured `gamma ~ 0.19` and concluded v3 is
**matmul-bound**, i.e. that the pre-hash gate contributes only ~16% of the cost
and the `2^eps * p` term is a minor correction. On accelerated silicon that
inverts: the matmul is cheap enough that feeding the gate becomes the
constraint. **The regime is a property of the hardware, not of the protocol**,
so a calibration derived on a CPU does not transfer to the machines that will
actually mine. Both limits of the closed form are therefore reachable in
practice, and the harmonic form must be used rather than either limit.

## How this compares to the candidates

| candidate | value | vs. this measurement |
| --- | --- | --- |
| shipped (neutral) | 1 | 122,140x too tight |
| **single-rig measurement** | **122,140** | — |
| MAC-ratio anchor `2^14 * 1027` | 16,826,368 | 138x too loose |
| discarded staged value | 16,893,794 | 138x too loose |

The discarded value was reached by dividing a SHA grind rate by an episode rate
— arithmetically meaningless — yet lands within ~2 orders of magnitude of a
real measurement, and on the *safe* side. That is a coincidence and must not be
read as vindication.

## What this does NOT settle

- **This rig runs v3's sigma stage on 24 CPU cores while RC runs on the GPU.** A
  real miner accelerates both. Raising `R_sigma` raises `k`, so treat 122,140 as
  a lower-bound-shaped anchor for this hardware class, not a final constant.
- Single process, no multi-GPU or multi-socket scaling, no pool topology.
- `R_M` is inferred from `matmul`-mode `digest_requests`, which appears to
  undercount under the parallel solver; the headline `k` does not depend on it
  (`R_eff` is a direct count), but the quoted `gamma` does.
- Difficulty is taken as 3.531677073810059 (height 176,445). `k` is only weakly
  and one-sidedly dependent on it. This was a measurement-time proposal; the
  current candidate instead installs a statically reviewed chain-parameter
  coefficient whose transition target is derived from the live parent nBits.

## Before anything is installed

Repeat on a rig that accelerates the v3 sigma stage as a miner would, repeat on
Apple silicon to get the cross-vendor spread of the *ratio*, and resolve the
unexplained RC episode-time swing between the 2026-07-30 (21.2 s) and
2026-08-01/02 (32.2 s) campaigns on nominally identical hardware — a 52% change
that no current artifact accounts for and that moves `k` proportionally.

## Artifacts

- `raw/v3-regime-measurements.json` — the raw sample set and derived values.

Contains machine-class and provider capability data only: no hostname, account
name, filesystem path, device serial, network address, or credential.
