// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license.
//
// PR-89 GPU splice #1 — provider-neutral Poseidon2 ROW-LEAF accelerator.
//
// Device-side implementation of the alg_hash row-leaf sponge
// (LeafHashRow / StreamingRowHasher semantics, B256 mode, untagged lane):
//   leaf i absorbs Canonical(c0),Canonical(c1),Canonical(c2) for every column
//   in commit order, then Fp(i), then the 10* pad (append 1, zero-fill to the
//   next rate-8 multiple), add-absorbing into rate lanes with a Permute at
//   every 8th position; digest = state[0..4).
//
// The API is streaming and column-block oriented so the caller never needs the
// whole [3W][n_lde] LDE resident on either host or device:
//   Begin  -> allocates n_lde resident sponge states (n_lde * 12 u64, zeroed)
//   Absorb -> one lane-major block blk[k*n_lde + i], absorb positions
//             base_pos..base_pos+n_lanes-1 (base_pos = 3*first_column)
//   Finalize -> index + pad, downloads [n_lde][4] digests, frees the context
//
// Poseidon2 round constants are NOT baked in: the caller uploads them at
// runtime from the production GetAlgHashConstants() via SetConstants, so the
// device permutation can never drift from the consensus constants.
//
// All functions return 0 on success / nonzero on failure and never exit().
// CUDA and Apple Metal provide the same exact C ABI. Other builds link
// matmul_v4_rc_rowleaf_gpu_stub.cpp (Available()==0).

#ifndef BITCOIN_MATMUL_MATMUL_V4_RC_ROWLEAF_GPU_H
#define BITCOIN_MATMUL_MATMUL_V4_RC_ROWLEAF_GPU_H

#include <cstdint>

extern "C" {

/** 1 iff a usable CUDA or Apple Metal provider is present. */
int BtxGpuRowLeafAvailable(void);

/** Upload Poseidon2-GL12 constants (from GetAlgHashConstants()). rc_ext is
 *  row-major [8][12]. Identical repeated uploads are idempotent; a provider
 *  may reject replacement with different bytes after initialization. Must
 *  precede Begin. Returns 0 on success. */
int BtxGpuRowLeafSetConstants(const uint64_t* rc_ext_8x12,
                              const uint64_t* rc_int_22,
                              const uint64_t* mu_12);

/** Allocate a streaming row-commit context with n_lde resident sponges. */
int BtxGpuRowLeafBegin(uint32_t n_lde, void** ctx_out);

/** Absorb one lane-major block: value for row i, absorb position base_pos+k,
 *  is blk[k*n_lde + i]. Values may be any u64 (canonicalized on device).
 *  Blocks must be presented in strictly increasing base_pos order with no
 *  gaps (base_pos == number of values absorbed so far). */
int BtxGpuRowLeafAbsorb(void* ctx, const uint64_t* blk, uint32_t n_lanes,
                        uint64_t base_pos);

/** Finalize: absorb Fp(i) then the 10* pad; write digests[i*4+r] (canonical)
 *  and free the context. total_vals must equal 3*W (values absorbed). */
int BtxGpuRowLeafFinalize(void* ctx, uint64_t total_vals,
                          uint64_t* out_digests);

/** Free a context on an error path (safe on nullptr). */
void BtxGpuRowLeafRelease(void* ctx);

} // extern "C"

#endif // BITCOIN_MATMUL_MATMUL_V4_RC_ROWLEAF_GPU_H
