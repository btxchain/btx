// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Apple Metal first-slice accelerator for the Stage-3 Fp3 NTT/LDE.
//
// The interface deliberately does not derive roots on the device.  The caller
// uploads the exact base-field root-power tables used by the consensus CPU
// implementation:
//
//   forward_roots[j] = omega_n^j,          0 <= j < n/2
//   inverse_roots[j] = (omega_n^-1)^j,     0 <= j < n/2
//   inverse_n        = n^-1 in Goldilocks.
//
// A context owns immutable root buffers and one reusable n-element Fp3 work
// buffer.  ForwardLde accepts coefficients in ascending-degree AoS order and
// returns evaluations in natural subgroup order:
//
//   out[i] = sum_j coeffs[j] * omega_n^(i*j).
//
// Inverse accepts natural-order evaluations and returns ascending-degree
// coefficients.  Input limbs may be any uint64_t; every limb is reduced to
// its canonical Goldilocks representative before the first butterfly.
//
// The context is single-operation-at-a-time.  Separate contexts may be used
// concurrently.  All functions return 0 on success, -1 for an invalid caller
// request, and -2 for a Metal allocation/compilation/execution failure.

#ifndef BITCOIN_MATMUL_MATMUL_V4_RC_FP3_LDE_GPU_H
#define BITCOIN_MATMUL_MATMUL_V4_RC_FP3_LDE_GPU_H

#include <cstdint>

extern "C" {

/** 1 iff a usable Apple Metal provider is present. */
int BtxMetalFp3LdeAvailable(void);

/**
 * Create a reusable transform context for a power-of-two domain.
 *
 * For domain_size > 1, both root arrays must contain exactly domain_size / 2
 * entries.  For domain_size == 1, both arrays may be null and their counts
 * must be zero.  Root values and inverse_n may be non-canonical uint64_t
 * representatives; the shader canonicalizes them before use.
 */
int BtxMetalFp3LdeBegin(uint32_t domain_size,
                        const uint64_t* forward_roots,
                        uint32_t forward_root_count,
                        const uint64_t* inverse_roots,
                        uint32_t inverse_root_count,
                        uint64_t inverse_n,
                        void** ctx_out);

/**
 * Zero-pad coeff_count ascending-degree Fp3 coefficients to domain_size and
 * evaluate them on the domain.  Arrays use AoS limb order
 * [c0,c1,c2, c0,c1,c2, ...].  coeffs may be null only when coeff_count == 0.
 */
int BtxMetalFp3LdeForward(void* ctx,
                          const uint64_t* coeffs_aos,
                          uint32_t coeff_count,
                          uint64_t* out_evals_aos);

/**
 * Inverse-transform domain_size natural-order evaluations into
 * ascending-degree coefficients.  Arrays use the same AoS limb order.
 */
int BtxMetalFp3LdeInverse(void* ctx,
                          const uint64_t* evals_aos,
                          uint64_t* out_coeffs_aos);

/** Release a context (safe on nullptr). */
void BtxMetalFp3LdeRelease(void* ctx);

} // extern "C"

#endif // BITCOIN_MATMUL_MATMUL_V4_RC_FP3_LDE_GPU_H
