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
// (MatExpand → Extract → project → combine). s8xs8 prefers hipBLASLt/rocBLAS
// MFMA when self-qualified; s32xs8 / MFMA decline use scalar DeviceGemm*
// (never labeled MFMA). Host ExactGemm is fail-closed fallback.
//
// Target arches: gfx942 (MI300), gfx950 (MI350) via BTX_HIP_ARCHITECTURES.
// Linker stub when BTX_ENABLE_HIP is off.
// ---------------------------------------------------------------------------

namespace matmul_v4::hip {

/** True iff HIP is enabled, an AMD GPU is present, and the one-time
 *  device bit-identity self-test passed. */
[[nodiscard]] bool IsMatMulLTHipAvailable();

/** Bit-exact device GEMMs backing MatExpand / projection stages, exported so
 *  a matmul::v4::lt::ExactGemmBackend can point its callbacks at them.
 *  Prefer MFMA library → device ALU → pooled scalar tile. Never label ALU as
 *  MFMA. Stub returns false when BTX_ENABLE_HIP is off. */
[[nodiscard]] bool LaunchGemmS8S8(const std::vector<int8_t>& left,
                                  const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t inner, uint32_t cols,
                                  std::vector<int32_t>& out);
[[nodiscard]] bool LaunchGemmS32S8(const std::vector<int32_t>& left,
                                   const std::vector<int8_t>& right,
                                   uint32_t rows, uint32_t inner, uint32_t cols,
                                   std::vector<int32_t>& out);

/** Digest-only ENC-DR-LT mining entry. Prefers the persistent device-resident
 *  loop; falls back to host ExactGemm on decline. Digests are byte-identical
 *  to ComputeDigestBMX4CLT. */
[[nodiscard]] bool ComputeDigestsOnlyLTHip(const CBlockHeader& tmpl, uint32_t n,
                                          const uint64_t* nonces, size_t count,
                                          std::vector<matmul::v4::lt::DigestOnlyResultLT>& out);

/** True iff most recent LaunchGemmS8S8 used hipBLASLt/rocBLAS MFMA. */
[[nodiscard]] bool LtLastS8S8UsedMfma();

} // namespace matmul_v4::hip

#endif // BITCOIN_HIP_MATMUL_V4_LT_ACCEL_H
