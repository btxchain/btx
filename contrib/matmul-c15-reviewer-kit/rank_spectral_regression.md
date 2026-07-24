# Rank / spectral regression note (C-15)

**Status: C-15 OPEN** — documentation aid, not a security proof.

## Claim

For honest MatExpand accumulators

```
Y  = G · W     # n×n · n×w → n×w
B32 = Y · H    # n×w · w×n → n×n
```

with production panel width `w = kMatExpandPanelW = 1024`, we have

```
rank(B32) ≤ w ≤ 1024
```

over the integers (and therefore over any field of characteristic 0 or large
prime). At production `n = 4096`, a linear Extract would reopen an
approximately `n/w = 4×` Freivalds-style shortcut that skips the dense
MatExpand GEMMs.

## Why Extract matters

The Lever-B construction uses one position-salted ChaCha stream plus M11
rejection over each real 32-value tile and one discrete scale `e∈{0..3}`.
It is the candidate that prevents treating `B̂` as an affine image of `B32`. Without that
nonlinearity, the low-rank factorization of `B32` is the attack surface
(LT-C15). External review of Extract is still required before activation.

## Smoke check (no node build)

```bash
python3 toy_attack_harness.py --n 32 --w 4
python3 spectral_approx_probe.py          # SVD/CCA vs Extract, n∈{32,64}
```

The harness builds synthetic `(G·W)·H`, prints `rank(B32)`, and asserts it is
`≤ w` (warns otherwise). Production `w=1024` is recorded in `test-vectors.json`
as `production_panel_w`. For post-Extract spectral / CCA residuals and the
**§0.1-win-required** rule, see [`spectral_approx_probe.md`](spectral_approx_probe.md).

## What this does *not* prove

- It does not bound the best degree-`d` approximant of Extract at production
  `n`.
- It does not replace Freivalds soundness arguments in the sketch domain.
- It does not close C-15. Empirics alone ≠ packet §0.1 FAIL.

See `doc/btx-matmul-v4.4-lt-external-c15-packet.md`.
