# v4/BMX4C activation-block timing (toy dims)

Regtest probe on Blackwell-class 16 GiB CUDA (CC 12.0), `regtestmatmulv4dimension=128`,
v4/BMX4C at height 100, RC at 101.

## Result

| Phase | Wall time |
|---|---|
| Pre-v4 mean | ~0.21 s |
| **Height 100 (v4/BMX4C activation)** | **~1.25 s** |
| Height 101 (RC activation) | ~0.33–0.37 s |
| Post-RC mean | ~0.24–0.26 s |

Debug log on the activation block: first `MatMul-v4 mining backend: cuda … sm_120` selection.

## Interpretation

The previously reported ~35 s activation on an ephemeral cloud GPU is **not** reproduced on a warm local CUDA host. It is best explained as **cold driver/context/JIT + first backend selection**, not steady-state validation cost. After that one-time spike, toy RC blocks stay sub-second.

Production Profile‑1 dims still need their own activation-day measurement.
