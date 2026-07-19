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
// NVIDIA backend for MatMul v4.4 ENC-DR-LT (MatExpand). Digests are
// bit-identical to matmul::v4::lt::ComputeDigestBMX4CLT. When a CUDA device
// is present and the one-time ExactGemm self-test passes, MatExpand's two
// dense GEMMs (G*W and (G*W)*H) run on device via ExactGemmBackend injected
// into WindowSketchMinerLT; otherwise the same miner runs on CPU ExactGemm*
// (backend_status=Fallback). Linker stub when BTX_ENABLE_CUDA is off.
// ---------------------------------------------------------------------------

namespace matmul_v4::cuda {

/** True iff this build was compiled with CUDA (BTX_ENABLE_CUDA_EXPERIMENTAL),
 *  a CUDA device is present, and the one-time device-GEMM bit-exactness
 *  self-test has not permanently failed. Callers should treat "false" only
 *  as "this backend cannot help"; ComputeDigestsOnlyLTCuda still always
 *  produces bit-exact results (or returns false) even when the underlying
 *  device GEMM offload is unavailable, because it falls back to the CPU
 *  reference pipeline in that case. */
[[nodiscard]] bool IsMatMulLTCudaAvailable();

/** Bit-exact device GEMMs backing the two dense MatExpand operand stages,
 *  exported so a matmul::v4::lt::ExactGemmBackend can point its callbacks
 *  straight at them (signatures match ExactGemmBackend::S8S8Fn / S32S8Fn).
 *  Each computes D(rows x cols) = L(rows x inner) * R(inner x cols) row-major
 *  with true integer accumulation identical to matmul::v4::lt::ExactGemmS8S8 /
 *  ExactGemmS32S8, returning false on any CUDA error so the caller falls back
 *  to the CPU reference. Defined only in the CUDA build (the stub TU omits
 *  them); reference them exclusively from CUDA code paths. */
[[nodiscard]] bool LaunchGemmS8S8(const std::vector<int8_t>& left,
                                  const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t inner, uint32_t cols,
                                  std::vector<int32_t>& out);
[[nodiscard]] bool LaunchGemmS32S8(const std::vector<int32_t>& left,
                                   const std::vector<int8_t>& right,
                                   uint32_t rows, uint32_t inner, uint32_t cols,
                                   std::vector<int32_t>& out);

/** Digest-only ENC-DR-LT mining entry: mine every nonce in `nonces` against
 *  the shared `tmpl` at dimension `n`. `out[i]` mirrors
 *  matmul::v4::lt::DigestOnlyResultLT for `nonces[i]`: `digest` is
 *  BYTE-IDENTICAL to matmul::v4::lt::ComputeDigestBMX4CLT(header_i, n, ...)
 *  where header_i is `tmpl` with the nonce bound in exactly the way
 *  matmul::v4::lt::WindowSketchMinerLT binds it. `target_match` is always
 *  false here (no target is supplied by this signature -- callers that need
 *  target filtering should compare `out[i].digest` themselves); this is a
 *  pure telemetry field per DigestOnlyResultLT's own contract ("consensus
 *  never sees this"). `backend_status` is Ok when a calibrated device GEMM
 *  path produced the result, Fallback when the host-exact
 *  WindowSketchMinerLT pipeline produced it (still bit-exact, just not
 *  device-accelerated), and this function returns false only on a
 *  structural failure (`n` invalid for ENC-DR-LT, `tmpl` does not admit a
 *  valid MatExpand window, `nonces` is null/empty, or the host reference
 *  itself rejects the template). On false, `out` is cleared. */
[[nodiscard]] bool ComputeDigestsOnlyLTCuda(const CBlockHeader& tmpl, uint32_t n,
                                            const uint64_t* nonces, size_t count,
                                            std::vector<matmul::v4::lt::DigestOnlyResultLT>& out);

} // namespace matmul_v4::cuda

#endif // BITCOIN_CUDA_MATMUL_V4_LT_ACCEL_H
