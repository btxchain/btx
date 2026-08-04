> **Historical provenance / current deferral.** This document preserves a dated
> design, audit, or measurement record; its body is not the current activation
> plan. Current source keeps public-network Epoch A (`v4 = BMX4C = RC`) disabled
> at `INT32_MAX`, with RC ASERT `1/1` and GPU-lifecycle ratification false. The
> signed annotated `v0.33.2` tag identifies an earlier `H=185000` source tree; no
> GitHub v0.33.2 release or assets were published; no v0.33.2 release binaries
> were published. The tag has not moved and is not corrective; changing its
> disposition requires an explicit release decision. See the
> [canonical transition roadmap](btx-matmul-v4.7-transition-roadmap.md).

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
