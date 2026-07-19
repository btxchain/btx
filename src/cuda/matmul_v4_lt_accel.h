// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_MATMUL_V4_LT_ACCEL_H
#define BITCOIN_CUDA_MATMUL_V4_LT_ACCEL_H

#include <matmul/matmul_v4_lt.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <vector>

class CBlockHeader;

// ---------------------------------------------------------------------------
// NVIDIA backend for MatMul v4.4 ENC-DR-LT (MatExpand).
//
// Digests are bit-identical to matmul::v4::lt::ComputeDigestBMX4CLT.
//
// When a CUDA device is present and the one-time bit-identity self-test
// passes, ComputeDigestsOnlyLTCuda runs a persistent device-resident loop:
//   MatExpand (G*W, Y*H) → ExtractDequant → project (Bhat*V) → F_q combine,
// with CUDA-graph replay of the stable GEMM stages and cross-call buffer
// reuse (per-nonce H2D limited to the thin W panel). Host ExactGemm* /
// WindowSketchMinerLT is the fail-closed fallback when the device path
// declines — not the complete accelerator.
//
// Linker stub when BTX_ENABLE_CUDA is off.
// ---------------------------------------------------------------------------

namespace matmul_v4::cuda {

/** True iff this build was compiled with CUDA (BTX_ENABLE_CUDA_EXPERIMENTAL),
 *  a CUDA device is present, and the one-time device bit-identity self-test
 *  (GEMMs + one full device-resident digest vs ComputeDigestBMX4CLT) has
 *  not permanently failed. Callers should treat "false" only as "this
 *  backend cannot help"; ComputeDigestsOnlyLTCuda still produces bit-exact
 *  results via the host ExactGemm fail-closed fallback when the device
 *  path is unavailable (except the ENABLE=OFF stub, which declines). */
[[nodiscard]] bool IsMatMulLTCudaAvailable();

/** Bit-exact device GEMMs backing MatExpand / projection stages, exported so
 *  a matmul::v4::lt::ExactGemmBackend can point its callbacks at them
 *  (signatures match ExactGemmBackend::S8S8Fn / S32S8Fn). Uses the process-
 *  persistent scratch pool (cross-call reuse). Returns false on any CUDA
 *  error so the caller falls back to CPU ExactGemm*. Defined only in the
 *  CUDA build (the stub TU omits them). */
[[nodiscard]] bool LaunchGemmS8S8(const std::vector<int8_t>& left,
                                  const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t inner, uint32_t cols,
                                  std::vector<int32_t>& out);
[[nodiscard]] bool LaunchGemmS32S8(const std::vector<int32_t>& left,
                                   const std::vector<int8_t>& right,
                                   uint32_t rows, uint32_t inner, uint32_t cols,
                                   std::vector<int32_t>& out);

/** Digest-only ENC-DR-LT mining entry: mine every nonce in `nonces` against
 *  the shared `tmpl` at dimension `n`. Prefers the persistent device-resident
 *  MatExpand→project→combine loop; falls back to host ExactGemm /
 *  WindowSketchMinerLT on decline. `out[i].digest` is BYTE-IDENTICAL to
 *  matmul::v4::lt::ComputeDigestBMX4CLT for the corresponding header.
 *  `target_match` is always false (no target in this signature).
 *  `backend_status` is Ok when the device path served the window, Fallback
 *  when host ExactGemm produced it (still bit-exact). Returns false only on
 *  structural failure; on false, `out` is cleared. */
[[nodiscard]] bool ComputeDigestsOnlyLTCuda(const CBlockHeader& tmpl, uint32_t n,
                                            const uint64_t* nonces, size_t count,
                                            std::vector<matmul::v4::lt::DigestOnlyResultLT>& out);

} // namespace matmul_v4::cuda

#endif // BITCOIN_CUDA_MATMUL_V4_LT_ACCEL_H
