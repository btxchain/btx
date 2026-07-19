# MatExpand Extract — full-width position salt `(i,j)`

**Normative packing** (CPU, AccelReplica, CUDA, HIP — bit-identical):

```
nonce_second = (uint64_t{i} << 32) | uint64_t{j}
```

- `i` and `j` are **full-width `uint32_t`** (ChaCha nonce bits `[63:32]` and `[31:0]`).
- Device kernels **MUST NOT truncate** either half (e.g. to 16 bits / `uint16_t` /
  mask `0xffff`). Truncation would:
  1. **Consensus-split** vs the CPU golden path, and
  2. **Reopen a ~32× low-rank shortcut** on `B32 = (G·W)·H` (rank ≤ `w=128`)
     by collapsing distinct row/column salts into a smaller equivalence class.

**Witness:** `matexpand_position_salt_differential` in
`src/test/matmul_v4_lt_tests.cpp` — for fixed `raw`,
`Extract(raw,i,j) ≠ Extract(raw,i|(1<<16),j)` and
`≠ Extract(raw,i,j|(1<<16))`, with AccelReplica parity.

**Cross-link:** external C-15 brief
`doc/btx-matmul-v4.4-lt-external-c15-packet.md` §1 (nonce packing / C15-C).
