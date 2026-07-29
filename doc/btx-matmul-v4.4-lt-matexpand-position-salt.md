> **HISTORICAL — superseded by ENC_RC v4.6.** This is a dated record of an earlier
> design stage, retained for provenance. It does **not** describe the current shipping
> proof-of-work, which is the two-stage ENC_RC v4.6 design (profile-2 datacenter episode
> + profile-3 V3 coupled puzzle). For the current design see
> `doc/btx-matmul-v4.6-rc-characteristics-2026-07-22.md`. Activation remains disabled
> (`nMatMulRCHeight = nMatMulRCCoupledHeight = INT32_MAX`).

# MatExpand MX Extract — full-width tile position salt `(i,bj)`

**Normative packing** (CPU, AccelReplica, CUDA, HIP — bit-identical):

```
nonce_first  = uint32_t{bj} ^ 0x4D58424C  // 'MXBL'
nonce_second = (uint64_t{i} << 32) | uint64_t{bj}
```

- `i` and `bj=j/32` are **full-width `uint32_t`** (ChaCha nonce bits
  `[63:32]` and `[31:0]`). Each stream extracts one real adjacent 32-value
  `B32` tile; it is not 32 independent per-cell streams.
- Device kernels **MUST NOT truncate** either half (e.g. to 16 bits / `uint16_t` /
  mask `0xffff`). Truncation would:
  1. **Consensus-split** vs the CPU golden path, and
  2. Create tile-stream/scale equivalence classes that may reopen the current
     `n/w=4096/1024=4×` raw panel shortcut on `B32=(G·W)·H`. Exploitability
     remains an open C-15 question; truncation alone is already a correctness bug.

**Witness:** `matexpand_position_salt_differential` in
`src/test/matmul_v4_lt_tests.cpp` — for fixed synthetic-tile differential
input, adjacent rows and tile blocks disagree, a high row-half flip disagrees,
and AccelReplica parity holds. Reviewer probes over `B32` must use real
32-value tiles; see `contrib/matmul-c15-reviewer-kit/reference_extract.py`.

Legacy per-cell ChaChaCell packing `(i,j)` with `MANT`/`SCLE` lanes is retained
only for differential tests and is not normative after Lever-B MX.

**Cross-link:** external C-15 brief
`doc/btx-matmul-v4.4-lt-external-c15-packet.md` §1 (nonce packing / C15-C).
