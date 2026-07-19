// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HIP_MATMUL_V4_LT_ACCEL_H
#define BITCOIN_HIP_MATMUL_V4_LT_ACCEL_H

#include <matmul/matmul_v4_lt.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <vector>

class CBlockHeader;

// ---------------------------------------------------------------------------
// AMD ROCm/HIP backend for MatMul v4.4 ENC-DR-LT (MatExpand).
//
 // Digests are bit-identical to matmul::v4::lt::ComputeDigestBMX4CLT.
 // When an AMD GPU is present and the one-time bit-identity self-test passes,
 // ComputeDigestsOnlyLTHip runs a persistent device-resident loop
 // (MatExpand → Extract → project → combine) with hipGraph replay of stable
 // GEMM stages. Host ExactGemm / WindowSketchMinerLT is fail-closed fallback
 // only — not the complete accelerator.
 //
 // Linker stub when BTX_ENABLE_HIP is off.
// ---------------------------------------------------------------------------

namespace matmul_v4::hip {

/** True iff HIP is enabled, an AMD GPU is present, and the one-time
 *  device bit-identity self-test passed. */
[[nodiscard]] bool IsMatMulLTHipAvailable();

/** Digest-only ENC-DR-LT mining entry. Prefers the persistent device-resident
 *  loop; falls back to host ExactGemm on decline. Digests are byte-identical
 *  to ComputeDigestBMX4CLT. */
[[nodiscard]] bool ComputeDigestsOnlyLTHip(const CBlockHeader& tmpl, uint32_t n,
                                          const uint64_t* nonces, size_t count,
                                          std::vector<matmul::v4::lt::DigestOnlyResultLT>& out);

} // namespace matmul_v4::hip

#endif // BITCOIN_HIP_MATMUL_V4_LT_ACCEL_H
