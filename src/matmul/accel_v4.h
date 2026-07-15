// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_ACCEL_V4_H
#define BTX_MATMUL_ACCEL_V4_H

#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

class CBlockHeader;

// MatMul v4 GPU-mining DISPATCH / INTEGRATION layer.
//
// This header is the BACKEND CONTRACT that every device backend (CUDA / Metal /
// HIP) plugs into, mirroring the v3 `matmul::accelerated` layer. It sits between
// the miner (src/pow.cpp SolveMatMulV4) and the pure-integer v4 reference in
// matmul/pow_v4.h + matmul/matmul_v4.h.
//
// CORRECTNESS INVARIANT (consensus-critical): a device backend MUST reproduce
// the CPU reference (matmul_v4::ComputeDigest) BYTE-FOR-BYTE -- the same
// `digest_out` and the same sketch `payload_out`, so the result passes
// matmul_v4::VerifySketch against the honest operands A,B regenerated on the
// host. The dispatcher NEVER trusts a device result: it re-verifies every
// accepted digest with matmul_v4::VerifySketch (the O(n^2) sketch-Freivalds
// check over q = 2^61-1) and, on ANY mismatch or device/setup error, discards
// the device output and falls back to the CPU reference. A GPU that computes a
// wrong digest can therefore never win a block; it only ever loses throughput.
//
// BIT-EXACTNESS: v4 is pure integer arithmetic (balanced-s8 operands, exact
// INT32 product, F_q sketch). Backends MUST NOT introduce floating point and
// MUST preserve the canonical element / serialization order (index-major
// A/B/U/V, row-major C, little-endian F_q words) documented in matmul_v4.h.

namespace matmul_v4::accel {

/** Device families a v4 digest can be dispatched to. CPU is always available
 *  and is the verification / fallback reference. */
enum class Kind { CPU, CUDA, METAL, HIP };

/** Host-callable per-backend entry point. MUST reproduce the CPU reference
 *  byte-for-byte: `digest_out` + `payload_out` identical to
 *  matmul_v4::ComputeDigest, so the pair passes matmul_v4::VerifySketch.
 *  Return false on any device/setup error (the dispatcher then falls back). */
using AccelFn = bool (*)(const CBlockHeader&, uint32_t n, uint32_t rounds,
                         uint256& digest_out, std::vector<unsigned char>& payload_out);

/** Runtime counters for the dispatch layer (probe via ProbeStats). `*_ok`
 *  counts device results that passed CPU verification and were accepted;
 *  `*_mismatch` counts device results that FAILED CPU verification (a wrong
 *  digest that was rejected); `*_fallback` counts every fall-through to the CPU
 *  reference (device error OR verification mismatch). */
struct Stats {
    uint64_t requests{0};
    uint64_t cuda_ok{0};
    uint64_t cuda_mismatch{0};
    uint64_t cuda_fallback{0};
    uint64_t metal_ok{0};
    uint64_t metal_mismatch{0};
    uint64_t metal_fallback{0};
    uint64_t hip_ok{0};
    uint64_t hip_mismatch{0};
    uint64_t hip_fallback{0};
};

/** Human-readable backend label ("cpu" / "cuda" / "metal" / "hip"). */
std::string ToString(Kind kind);

/** Select the best available backend from device capabilities and the
 *  BTX_MATMUL_V4_BACKEND environment variable (values: cpu, cuda, metal, hip;
 *  aliases rocm->hip, mlx->metal). An unset/empty value defaults to metal on
 *  Apple and cpu elsewhere. If the requested backend is unavailable (not
 *  compiled in, or its capability probe reports unavailable), this resolves to
 *  Kind::CPU and logs the reason once. */
Kind ResolveBackend();

/** Compute the v4 consensus digest + sketch payload via the resolved backend,
 *  VERIFY the result with matmul_v4::VerifySketch, and fall back to the CPU
 *  reference (matmul_v4::ComputeDigest) on any mismatch or error. This is what
 *  SolveMatMulV4 calls per nonce. Returns false only if the CPU reference
 *  itself rejects the shape (invalid (n, b); see matmul_v4::ComputeDigest). */
[[nodiscard]] bool ComputeDigestDispatched(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                                           uint256& digest_out, std::vector<unsigned char>& payload_out);

/** Snapshot the runtime dispatch counters. */
Stats ProbeStats();

/** Reset the runtime dispatch counters (test / benchmark harness). */
void ResetStats();

} // namespace matmul_v4::accel

// ---------------------------------------------------------------------------
// DEVICE BACKEND ENTRY POINTS (the plug-in surface).
//
// Each device backend implements exactly ONE of these functions -- a strong
// definition compiled into btx_matmul_backend when the backend's CMake define
// is enabled (BTX_ENABLE_CUDA_EXPERIMENTAL / BTX_ENABLE_METAL /
// BTX_ENABLE_HIP_EXPERIMENTAL). When a backend is NOT compiled in, a weak stub
// (matmul/accel_v4_stub.cpp) provides a definition that returns false, so the
// dispatch layer links and runs CPU-only. The signatures match AccelFn exactly.
// ---------------------------------------------------------------------------

namespace matmul_v4::cuda {
[[nodiscard]] bool ComputeDigestAccel(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                                      uint256& digest_out, std::vector<unsigned char>& payload_out);
} // namespace matmul_v4::cuda

namespace matmul_v4::metal {
[[nodiscard]] bool ComputeDigestAccel(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                                      uint256& digest_out, std::vector<unsigned char>& payload_out);
} // namespace matmul_v4::metal

namespace matmul_v4::hip {
[[nodiscard]] bool ComputeDigestAccel(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                                      uint256& digest_out, std::vector<unsigned char>& payload_out);
} // namespace matmul_v4::hip

#endif // BTX_MATMUL_ACCEL_V4_H
