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

/** Host-callable per-backend BATCHED entry point (v4.1 §K.2b cross-nonce
 *  window). Mirrors AccelFn but computes a whole nonce window at once: given a
 *  vector of fully-populated candidate `headers` (all projecting onto one
 *  template — nNonce64 / §H.4 seeds set per candidate exactly as SolveMatMulV4
 *  does), dimension `n`, and `rounds`, it fills `digests_out[i]` /
 *  `payloads_out[i]` for header i. Each pair MUST reproduce
 *  matmul_v4::ComputeDigest(headers[i], ...) BYTE-FOR-BYTE, so every pair
 *  passes matmul_v4::VerifySketch. `digests_out` and `payloads_out` MUST be
 *  sized to headers.size() on success. Return false on any device/setup error
 *  (the dispatcher then falls back to the CPU batched reference). This is the
 *  fixed signature every GPU backend (matmul_v4::{cuda,metal,hip}) implements. */
using BatchAccelFn = bool (*)(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                              std::vector<uint256>& digests_out,
                              std::vector<std::vector<unsigned char>>& payloads_out);

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

    // BATCHED dispatch counters (ComputeDigestsBatchedDispatched). One request
    // is one nonce WINDOW. `*_batch_ok` counts windows where EVERY returned
    // (digest,payload) passed CPU verification and the whole window was
    // accepted; `*_batch_mismatch` counts windows where the device output
    // failed CPU verification (a wrong digest, rejected); `*_batch_fallback`
    // counts every window that fell through to the CPU batched reference
    // (device error, wrong window size, OR verification mismatch).
    uint64_t batch_requests{0};
    uint64_t cuda_batch_ok{0};
    uint64_t cuda_batch_mismatch{0};
    uint64_t cuda_batch_fallback{0};
    uint64_t metal_batch_ok{0};
    uint64_t metal_batch_mismatch{0};
    uint64_t metal_batch_fallback{0};
    uint64_t hip_batch_ok{0};
    uint64_t hip_batch_mismatch{0};
    uint64_t hip_batch_fallback{0};
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

/** Compute a whole nonce WINDOW's digests + sketch payloads via the resolved
 *  backend's BATCHED path (§K.2b), VERIFY every returned (digest,payload) with
 *  matmul_v4::VerifySketch (re-deriving the honest operands on the host per
 *  header), and fall back to the CPU reference on ANY mismatch, wrong window
 *  size, or device error. The safety contract is identical to the per-nonce
 *  ComputeDigestDispatched, extended to a window: a single wrong device digest
 *  anywhere in the window discards the WHOLE device result and recomputes the
 *  window on the CPU, so a bad device output can never be mined. On the CPU
 *  fallback / CPU-resolved path each nonce is computed with the byte-exact
 *  matmul_v4::ComputeDigest reference (equivalently reproducible by
 *  matmul::v4::BatchedSketchMiner). `digests_out` / `payloads_out` are sized to
 *  headers.size() on success. Returns false only if `headers` is empty or the
 *  CPU reference itself rejects the shape (invalid (n, b)). This is what the
 *  measurement tool and (later) the batched GPU miner call. */
[[nodiscard]] bool ComputeDigestsBatchedDispatched(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                                   std::vector<uint256>& digests_out,
                                                   std::vector<std::vector<unsigned char>>& payloads_out);

/** ENC-BMX4C batched dispatch (MatMul v4.2 profile). The exact sibling of
 *  ComputeDigestsBatchedDispatched, for the ENC_BMX4C encoding profile: compute
 *  a whole nonce WINDOW's digests + sketch payloads via the resolved backend's
 *  ENC-BMX4C batched device path, VERIFY every returned (digest,payload) with
 *  matmul::v4::bmx4::VerifySketchBMX4C (re-deriving the honest M11+E8M0
 *  operands on the host per header), and fall back on ANY mismatch, wrong
 *  window size, or device error. The CPU-resolved and fallback path computes
 *  the window with matmul::v4::bmx4::BatchedSketchMinerBMX4C (byte-identical to
 *  the single-nonce matmul::v4::bmx4::ComputeDigestBMX4C reference, enforced by
 *  matmul_v4_bmx4_batch_tests), falling back to the single-nonce reference if
 *  the batch miner rejects the shape / template. `digests_out` / `payloads_out`
 *  are sized to headers.size() on success. Returns false only if `headers` is
 *  empty or the ENC-BMX4C reference itself rejects the shape (invalid (n, b) or
 *  n % 32 != 0). Same safety contract as the per-nonce / ENC-S8 paths: a single
 *  wrong device digest anywhere discards the WHOLE device window. */
[[nodiscard]] bool ComputeDigestsBMX4CDispatched(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                                 std::vector<uint256>& digests_out,
                                                 std::vector<std::vector<unsigned char>>& payloads_out);

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

// Each backend also implements the BATCHED entry point ComputeDigestsBatchedAccel
// (the fixed BatchAccelFn signature, §K.2b). Same weak-stub gating as the
// per-nonce ComputeDigestAccel: a strong device definition when the backend's
// CMake define is set, else the weak stub (accel_v4_stub.cpp) returns false.

// Each backend ALSO implements the ENC-BMX4C batched entry point
// ComputeDigestsBMX4CAccel (MatMul v4.2 profile; same fixed signature as
// ComputeDigestsBatchedAccel, one nonce window at a time). Same weak-stub
// gating: a strong device definition when the backend's CMake define is set,
// else the weak stub (accel_v4_stub.cpp) returns false. Each returned
// (digest,payload) MUST reproduce matmul::v4::bmx4::ComputeDigestBMX4C(headers[i])
// BYTE-FOR-BYTE, so it passes matmul::v4::bmx4::VerifySketchBMX4C.

namespace matmul_v4::cuda {
[[nodiscard]] bool ComputeDigestAccel(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                                      uint256& digest_out, std::vector<unsigned char>& payload_out);
[[nodiscard]] bool ComputeDigestsBatchedAccel(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                              std::vector<uint256>& digests_out,
                                              std::vector<std::vector<unsigned char>>& payloads_out);
[[nodiscard]] bool ComputeDigestsBMX4CAccel(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                            std::vector<uint256>& digests_out,
                                            std::vector<std::vector<unsigned char>>& payloads_out);
} // namespace matmul_v4::cuda

namespace matmul_v4::metal {
[[nodiscard]] bool ComputeDigestAccel(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                                      uint256& digest_out, std::vector<unsigned char>& payload_out);
[[nodiscard]] bool ComputeDigestsBatchedAccel(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                              std::vector<uint256>& digests_out,
                                              std::vector<std::vector<unsigned char>>& payloads_out);
[[nodiscard]] bool ComputeDigestsBMX4CAccel(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                            std::vector<uint256>& digests_out,
                                            std::vector<std::vector<unsigned char>>& payloads_out);
} // namespace matmul_v4::metal

namespace matmul_v4::hip {
[[nodiscard]] bool ComputeDigestAccel(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                                      uint256& digest_out, std::vector<unsigned char>& payload_out);
[[nodiscard]] bool ComputeDigestsBatchedAccel(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                              std::vector<uint256>& digests_out,
                                              std::vector<std::vector<unsigned char>>& payloads_out);
[[nodiscard]] bool ComputeDigestsBMX4CAccel(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                            std::vector<uint256>& digests_out,
                                            std::vector<std::vector<unsigned char>>& payloads_out);
} // namespace matmul_v4::hip

#endif // BTX_MATMUL_ACCEL_V4_H
