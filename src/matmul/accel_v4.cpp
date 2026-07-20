// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/accel_v4.h>

#include <arith_uint256.h>
#include <ascend/matmul_v4_lt_accel.h>
#include <cuda/matmul_v4_lt_accel.h>
#include <cuda/matmul_v4_lt_tensor_gemm.h>
#include <hip/matmul_v4_lt_accel.h>
#include <matmul/backend_capabilities_v4.h>
#include <matmul/exact_gemm_resolve.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_bmx4_batch.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc_selfqual.h>
#include <matmul/pow_v4.h>
#include <metal/matmul_v4_lt_accel.h>
#include <primitives/block.h>
#include <tpu/matmul_v4_lt_accel.h>
#include <trainium/matmul_v4_lt_accel.h>
#include <logging.h>

#include <atomic>
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <map>
#include <mutex>
#include <string>
#include <tuple>
#include <utility>
#include <string>
#include <vector>

namespace matmul_v4::accel {
namespace {

// ---- runtime dispatch counters (mirrors v3 BackendRuntimeStats plumbing) ----
std::atomic<uint64_t> g_requests{0};
std::atomic<uint64_t> g_cuda_ok{0};
std::atomic<uint64_t> g_cuda_mismatch{0};
std::atomic<uint64_t> g_cuda_fallback{0};
std::atomic<uint64_t> g_metal_ok{0};
std::atomic<uint64_t> g_metal_mismatch{0};
std::atomic<uint64_t> g_metal_fallback{0};
std::atomic<uint64_t> g_hip_ok{0};
std::atomic<uint64_t> g_hip_mismatch{0};
std::atomic<uint64_t> g_hip_fallback{0};
std::atomic<uint64_t> g_ascend_ok{0};
std::atomic<uint64_t> g_ascend_mismatch{0};
std::atomic<uint64_t> g_ascend_fallback{0};

std::atomic_bool g_logged_cuda_fallback{false};
std::atomic_bool g_logged_metal_fallback{false};
std::atomic_bool g_logged_hip_fallback{false};
std::atomic_bool g_logged_ascend_fallback{false};

// ---- batched dispatch counters (ComputeDigestsBatchedDispatched) ----
std::atomic<uint64_t> g_batch_requests{0};
std::atomic<uint64_t> g_cuda_batch_ok{0};
std::atomic<uint64_t> g_cuda_batch_mismatch{0};
std::atomic<uint64_t> g_cuda_batch_fallback{0};
std::atomic<uint64_t> g_metal_batch_ok{0};
std::atomic<uint64_t> g_metal_batch_mismatch{0};
std::atomic<uint64_t> g_metal_batch_fallback{0};
std::atomic<uint64_t> g_hip_batch_ok{0};
std::atomic<uint64_t> g_hip_batch_mismatch{0};
std::atomic<uint64_t> g_hip_batch_fallback{0};
std::atomic<uint64_t> g_ascend_batch_ok{0};
std::atomic<uint64_t> g_ascend_batch_mismatch{0};
std::atomic<uint64_t> g_ascend_batch_fallback{0};

std::atomic_bool g_logged_cuda_batch_fallback{false};
std::atomic_bool g_logged_metal_batch_fallback{false};
std::atomic_bool g_logged_hip_batch_fallback{false};
std::atomic_bool g_logged_ascend_batch_fallback{false};

std::string DefaultBackendRequest()
{
#if defined(__APPLE__)
    return "metal";
#else
    return "cpu";
#endif
}

// Convert a v4 certification-registry Kind (matmul_v4::backend::Kind) into the
// dispatch-layer Kind. The two enums mirror each other member-for-member
// (backend_capabilities_v4.h documents this contract), so this is a pure
// name-for-name map -- it exists so the dispatch layer can delegate the
// eligibility/admissibility decision to the registry and translate the result.
Kind FromBackendKind(matmul_v4::backend::Kind kind)
{
    switch (kind) {
    case matmul_v4::backend::Kind::CPU: return Kind::CPU;
    case matmul_v4::backend::Kind::CUDA: return Kind::CUDA;
    case matmul_v4::backend::Kind::METAL: return Kind::METAL;
    case matmul_v4::backend::Kind::HIP: return Kind::HIP;
    case matmul_v4::backend::Kind::ASCEND: return Kind::ASCEND;
    }
    return Kind::CPU;
}

// Address of the device entry point for `kind` (or nullptr for CPU). A weak
// stub always provides a definition, so these are never dangling; a stub simply
// returns false and the dispatcher falls back.
AccelFn DeviceFnFor(Kind kind)
{
    switch (kind) {
    case Kind::CUDA:
        return &matmul_v4::cuda::ComputeDigestAccel;
    case Kind::METAL:
        return &matmul_v4::metal::ComputeDigestAccel;
    case Kind::HIP:
        return &matmul_v4::hip::ComputeDigestAccel;
    case Kind::ASCEND:
        return &matmul_v4::ascend::ComputeDigestAccel;
    case Kind::CPU:
        return nullptr;
    }
    return nullptr;
}

// Address of the BATCHED device entry point for `kind` (or nullptr for CPU).
// A weak stub always provides a definition, so these are never dangling.
BatchAccelFn BatchDeviceFnFor(Kind kind)
{
    switch (kind) {
    case Kind::CUDA:
        return &matmul_v4::cuda::ComputeDigestsBatchedAccel;
    case Kind::METAL:
        return &matmul_v4::metal::ComputeDigestsBatchedAccel;
    case Kind::HIP:
        return &matmul_v4::hip::ComputeDigestsBatchedAccel;
    case Kind::ASCEND:
        return &matmul_v4::ascend::ComputeDigestsBatchedAccel;
    case Kind::CPU:
        return nullptr;
    }
    return nullptr;
}

// Address of the ENC-BMX4C BATCHED device entry point for `kind` (or nullptr
// for CPU). A weak stub always provides a definition, so these are never
// dangling.
BatchAccelFn BMX4CDeviceFnFor(Kind kind)
{
    switch (kind) {
    case Kind::CUDA:
        return &matmul_v4::cuda::ComputeDigestsBMX4CAccel;
    case Kind::METAL:
        return &matmul_v4::metal::ComputeDigestsBMX4CAccel;
    case Kind::HIP:
        return &matmul_v4::hip::ComputeDigestsBMX4CAccel;
    case Kind::ASCEND:
        return &matmul_v4::ascend::ComputeDigestsBMX4CAccel;
    case Kind::CPU:
        return nullptr;
    }
    return nullptr;
}

void RecordOk(Kind kind)
{
    switch (kind) {
    case Kind::CUDA: g_cuda_ok.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::METAL: g_metal_ok.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::HIP: g_hip_ok.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::ASCEND: g_ascend_ok.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::CPU: break;
    }
}

void RecordMismatch(Kind kind)
{
    switch (kind) {
    case Kind::CUDA: g_cuda_mismatch.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::METAL: g_metal_mismatch.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::HIP: g_hip_mismatch.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::ASCEND: g_ascend_mismatch.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::CPU: break;
    }
}

void RecordFallback(Kind kind, const std::string& reason)
{
    std::atomic<uint64_t>* counter = nullptr;
    std::atomic_bool* log_once = nullptr;
    const char* label = "";
    switch (kind) {
    case Kind::CUDA: counter = &g_cuda_fallback; log_once = &g_logged_cuda_fallback; label = "CUDA"; break;
    case Kind::METAL: counter = &g_metal_fallback; log_once = &g_logged_metal_fallback; label = "METAL"; break;
    case Kind::HIP: counter = &g_hip_fallback; log_once = &g_logged_hip_fallback; label = "HIP"; break;
    case Kind::ASCEND: counter = &g_ascend_fallback; log_once = &g_logged_ascend_fallback; label = "ASCEND"; break;
    case Kind::CPU: return;
    }
    counter->fetch_add(1, std::memory_order_relaxed);
    bool expected{false};
    if (log_once->compare_exchange_strong(expected, true)) {
        LogPrintf("MATMUL-V4 WARNING: %s backend fallback to CPU (%s)\n", label, reason);
    }
}

void RecordBatchOk(Kind kind)
{
    switch (kind) {
    case Kind::CUDA: g_cuda_batch_ok.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::METAL: g_metal_batch_ok.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::HIP: g_hip_batch_ok.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::ASCEND: g_ascend_batch_ok.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::CPU: break;
    }
}

void RecordBatchMismatch(Kind kind)
{
    switch (kind) {
    case Kind::CUDA: g_cuda_batch_mismatch.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::METAL: g_metal_batch_mismatch.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::HIP: g_hip_batch_mismatch.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::ASCEND: g_ascend_batch_mismatch.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::CPU: break;
    }
}

void RecordBatchFallback(Kind kind, const std::string& reason)
{
    std::atomic<uint64_t>* counter = nullptr;
    std::atomic_bool* log_once = nullptr;
    const char* label = "";
    switch (kind) {
    case Kind::CUDA: counter = &g_cuda_batch_fallback; log_once = &g_logged_cuda_batch_fallback; label = "CUDA"; break;
    case Kind::METAL: counter = &g_metal_batch_fallback; log_once = &g_logged_metal_batch_fallback; label = "METAL"; break;
    case Kind::HIP: counter = &g_hip_batch_fallback; log_once = &g_logged_hip_batch_fallback; label = "HIP"; break;
    case Kind::ASCEND: counter = &g_ascend_batch_fallback; log_once = &g_logged_ascend_batch_fallback; label = "ASCEND"; break;
    case Kind::CPU: return;
    }
    counter->fetch_add(1, std::memory_order_relaxed);
    bool expected{false};
    if (log_once->compare_exchange_strong(expected, true)) {
        LogPrintf("MATMUL-V4 WARNING: %s batched backend fallback to CPU (%s)\n", label, reason);
    }
}

// Byte-exact CPU reference for a whole window: each nonce via the single-nonce
// consensus reference matmul_v4::ComputeDigest (equivalently reproducible by
// matmul::v4::BatchedSketchMiner, enforced by matmul_v4_batch_tests). Used both
// for the CPU-resolved path and as the fallback when a device result is
// rejected. Returns false only if the shape (n, b) is invalid.
bool ComputeBatchCpuReference(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                              std::vector<uint256>& digests_out,
                              std::vector<std::vector<unsigned char>>& payloads_out)
{
    const size_t count = headers.size();
    digests_out.assign(count, uint256{});
    payloads_out.assign(count, std::vector<unsigned char>{});
    for (size_t i = 0; i < count; ++i) {
        if (!matmul_v4::ComputeDigest(headers[i], n, rounds, digests_out[i], payloads_out[i])) {
            digests_out.clear();
            payloads_out.clear();
            return false;
        }
    }
    return true;
}

// Byte-exact CPU reference for a whole ENC-BMX4C window. Prefers the batched
// miner (matmul::v4::bmx4::BatchedSketchMinerBMX4C — template-cached Ahat/U/V
// and P = U*Ahat, one stacked combine GEMM per window) keyed on the first
// header's template; on any shape/template rejection it falls back to the
// single-nonce matmul::v4::bmx4::ComputeDigestBMX4C reference. Both are
// byte-identical (matmul_v4_bmx4_batch_tests). Returns false only if the
// ENC-BMX4C reference rejects the shape (invalid (n, b) or n % 32 != 0).
bool ComputeBatchCpuReferenceBMX4C(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                   std::vector<uint256>& digests_out,
                                   std::vector<std::vector<unsigned char>>& payloads_out)
{
    const size_t count = headers.size();
    digests_out.assign(count, uint256{});
    payloads_out.assign(count, std::vector<unsigned char>{});

    // Fast path: all headers share a template (the solve loop's per-window
    // invariant) — mine the whole window with the batched miner.
    const matmul::v4::bmx4::BatchedSketchMinerBMX4C miner{headers.front(), n};
    if (miner.Valid()) {
        std::vector<matmul::v4::bmx4::BatchNonceResultBMX4C> results;
        if (miner.Mine(headers, results) && results.size() == count) {
            for (size_t i = 0; i < count; ++i) {
                digests_out[i] = results[i].digest;
                payloads_out[i] = std::move(results[i].payload);
            }
            return true;
        }
    }

    // Fallback: per-nonce single-nonce reference (also the shape-rejection path
    // — if this rejects the shape, the whole window is invalid).
    for (size_t i = 0; i < count; ++i) {
        uint256 digest;
        std::vector<unsigned char> payload;
        if (!matmul::v4::bmx4::ComputeDigestBMX4C(headers[i], n, digest, payload)) {
            digests_out.clear();
            payloads_out.clear();
            return false;
        }
        digests_out[i] = digest;
        payloads_out[i] = std::move(payload);
    }
    (void)rounds; // ENC-BMX4C miner runs no Freivalds (API symmetry)
    return true;
}

bool ComputeBatchCpuReferenceBMX4CLT(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                     std::vector<uint256>& digests_out,
                                     std::vector<std::vector<unsigned char>>& payloads_out)
{
    const size_t count = headers.size();
    digests_out.assign(count, uint256{});
    payloads_out.assign(count, std::vector<unsigned char>{});

    const matmul::v4::lt::WindowSketchMinerLT miner{
        headers.front(), n, MakeResolvedExactGemmBackend(),
        MakeResolvedExactMxProjectionBackend()};
    if (miner.Valid()) {
        const uint256 kNoTarget = ArithToUint256(~arith_uint256{});
        std::vector<matmul::v4::lt::DigestOnlyResultLT> results;
        if (miner.MineWindow(headers, kNoTarget, results) && results.size() == count) {
            for (size_t i = 0; i < count; ++i) {
                digests_out[i] = results[i].digest;
                uint256 d;
                std::vector<unsigned char> payload;
                if (!matmul::v4::lt::ComputeDigestBMX4CLT(headers[i], n, d, payload) ||
                    d != results[i].digest) {
                    digests_out.clear();
                    payloads_out.clear();
                    return false;
                }
                payloads_out[i] = std::move(payload);
            }
            (void)rounds;
            return true;
        }
    }

    for (size_t i = 0; i < count; ++i) {
        uint256 digest;
        std::vector<unsigned char> payload;
        if (!matmul::v4::lt::ComputeDigestBMX4CLT(headers[i], n, digest, payload)) {
            digests_out.clear();
            payloads_out.clear();
            return false;
        }
        digests_out[i] = digest;
        payloads_out[i] = std::move(payload);
    }
    (void)rounds;
    return true;
}

void DropLosingPayloadsBMX4CLT(const uint256& win_target,
                               const std::vector<uint256>& digests,
                               std::vector<std::vector<unsigned char>>& payloads)
{
    assert(digests.size() == payloads.size());
    const arith_uint256 target{UintToArith256(win_target)};
    for (size_t i = 0; i < digests.size(); ++i) {
        if (UintToArith256(digests[i]) > target) payloads[i].clear();
    }
}

bool TryDeviceDigestsBMX4CLT(Kind backend, const std::vector<CBlockHeader>& headers, uint32_t n,
                             const uint256& win_target,
                             std::vector<uint256>& digests_out,
                             std::vector<std::vector<unsigned char>>& payloads_out)
{
    digests_out.clear();
    payloads_out.clear();
    if (headers.empty()) return false;

    // CUDA/HIP accept the complete consensus-seeded header vector, so W
    // generation, digesting and the batch boundary remain on-device without
    // discarding nonce-bound seed_a/seed_b. Metal/Ascend retain the legacy
    // template+nonce ABI and therefore may batch only identical seed inputs.
    const CBlockHeader& tmpl = headers.front();
    auto same_consensus_inputs = [&](const CBlockHeader& h) {
        return h.seed_a == tmpl.seed_a && h.seed_b == tmpl.seed_b &&
               h.hashPrevBlock == tmpl.hashPrevBlock &&
               h.hashMerkleRoot == tmpl.hashMerkleRoot &&
               h.nTime == tmpl.nTime && h.nBits == tmpl.nBits &&
               h.nVersion == tmpl.nVersion;
    };
    const bool nonce_only_batch =
        std::all_of(headers.begin(), headers.end(), same_consensus_inputs);

    auto run_legacy_device = [&](const CBlockHeader& header, const uint64_t* nonces, size_t count,
                                 std::vector<matmul::v4::lt::DigestOnlyResultLT>& out) -> bool {
        switch (backend) {
        case Kind::METAL:
            return matmul_v4::metal::ComputeDigestsOnlyLTMetal(header, n, nonces, count, out);
        case Kind::ASCEND:
            return matmul_v4::ascend::ComputeDigestsOnlyLTAscend(header, n, nonces, count, out);
        case Kind::CUDA:
        case Kind::HIP:
        case Kind::CPU:
            return false;
        }
        return false;
    };

    std::vector<matmul::v4::lt::DigestOnlyResultLT> results;
    if (backend == Kind::CUDA) {
        matmul_v4::cuda::LtCudaBatchProvenance provenance;
        if (!matmul_v4::cuda::ComputeDigestsOnlyLTCuda(
                headers, n, results, &provenance) ||
            !provenance.device_w_generation || !provenance.device_digest ||
            !provenance.per_nonce_sync_absent ||
            (headers.size() > 1 && !provenance.qstar_device_batched)) {
            // The CUDA entry point deliberately has a bit-exact host fallback,
            // which may itself use individual device GEMMs and report Ok. That
            // is useful below the backend API, but it is not resident LT mining:
            // require the same provenance tuple used by performance telemetry
            // before accounting this as a successful device batch.
            return false;
        }
    } else if (backend == Kind::HIP) {
        matmul_v4::hip::LtHipBatchProvenance provenance;
        if (!matmul_v4::hip::ComputeDigestsOnlyLTHip(
                headers, n, results, &provenance) ||
            !provenance.device_w_generation || !provenance.device_digest ||
            !provenance.per_nonce_sync_absent ||
            (headers.size() > 1 && !provenance.qstar_device_batched)) {
            return false;
        }
    } else if (nonce_only_batch) {
        std::vector<uint64_t> nonces(headers.size());
        for (size_t i = 0; i < headers.size(); ++i) {
            nonces[i] = headers[i].nNonce64;
        }
        if (!run_legacy_device(tmpl, nonces.data(), nonces.size(), results) ||
            results.size() != headers.size()) {
            return false;
        }
    } else {
        results.resize(headers.size());
        for (size_t i = 0; i < headers.size(); ++i) {
            const uint64_t nonce = headers[i].nNonce64;
            std::vector<matmul::v4::lt::DigestOnlyResultLT> one;
            if (!run_legacy_device(headers[i], &nonce, 1, one) || one.size() != 1) {
                return false;
            }
            results[i] = std::move(one[0]);
        }
    }

    if (results.size() != headers.size() ||
        !std::all_of(results.begin(), results.end(), [](const auto& result) {
            return result.backend_status == matmul::v4::bmx4::DigestOnlyBackendStatus::Ok;
        })) {
        // A backend's internal host fallback is bit-exact, but it is not a
        // successful device batch. Let the dispatcher's explicit CPU fallback
        // own that path and its accounting.
        return false;
    }

    const arith_uint256 target = UintToArith256(win_target);
    digests_out.resize(headers.size());
    payloads_out.resize(headers.size());
    for (size_t i = 0; i < headers.size(); ++i) {
        digests_out[i] = results[i].digest;
        if (UintToArith256(results[i].digest) > target) {
            // Losing slots need only their digest. Reconstructing every Chat on
            // the host would erase the Q* device-batch speedup; potential
            // winners are still reference-resealed below before use.
            continue;
        }
        uint256 d;
        std::vector<unsigned char> payload;
        // Host-verify every potential winner against the COMPLETE candidate
        // header (including nonce-bound seeds) before handing over a sketch.
        if (!matmul::v4::lt::ComputeDigestBMX4CLT(headers[i], n, d, payload) ||
            d != results[i].digest) {
            digests_out.clear();
            payloads_out.clear();
            return false;
        }
        payloads_out[i] = std::move(payload);
    }
    return true;
}

} // namespace

std::string ToString(Kind kind)
{
    switch (kind) {
    case Kind::CPU: return "cpu";
    case Kind::CUDA: return "cuda";
    case Kind::METAL: return "metal";
    case Kind::HIP: return "hip";
    case Kind::ASCEND: return "ascend";
    }
    return "cpu";
}

Kind ResolveBackend()
{
    const char* const env = std::getenv("BTX_MATMUL_V4_BACKEND");
    const std::string requested = (env != nullptr && env[0] != '\0')
        ? std::string{env}
        : DefaultBackendRequest();

    // C7 (certification integrity): the runtime dispatch decision MUST consult
    // the v4 ADMISSIBILITY / CERTIFICATION registry (matmul/backend_capabilities
    // _v4.h), NOT merely the v3 "compiled + device present" capability table.
    // matmul_v4::backend::ResolveBackend resolves a backend to ACTIVE only when
    // it is compiled, available, AND §S.1-admissible -- i.e. it presents a
    // genuine bit-exact integer tensor path (the same predicate the report and
    // the cross-backend determinism harness certify against). An unknown,
    // unavailable, or INADMISSIBLE (verification-only) request resolves to CPU
    // with a machine-readable reason. Dispatching through this registry
    // guarantees the backend that actually RUNS is exactly the one certification
    // admitted: emulation / verification-only silicon can never be the DISPATCH
    // target in the first place. (The per-result matmul_v4::VerifySketch +
    // CPU-fallback safety net in ComputeDigest*Dispatched below is unchanged --
    // this fix is about not dispatching to an uncertified backend, not about the
    // consensus recompute.)
    const matmul_v4::backend::Selection selection =
        matmul_v4::backend::ResolveBackend(requested);
    const Kind active = FromBackendKind(selection.active);
    const Kind requested_kind = FromBackendKind(selection.requested);

    // Emit one clear line describing the RESOLVED v4 mining backend the first
    // time this is called (mirrors v3 ResolveMiningBackendFromEnvironment), so a
    // silent CPU fallback from an unavailable / inadmissible GPU request can
    // never hide.
    static std::atomic_bool logged_resolved{false};
    bool expected{false};
    if (logged_resolved.compare_exchange_strong(expected, true)) {
        if (selection.requested_known && active == requested_kind) {
            LogPrintf("MatMul-v4 mining backend: %s (requested=%s, %s)\n",
                      ToString(active), requested, selection.reason);
        } else {
            LogPrintf("MatMul-v4 mining backend: %s [WARNING: requested %s but the v4 "
                      "certification registry did not admit it -> %s]\n",
                      ToString(active), requested, selection.reason);
        }
    }

    return active;
}


namespace {

struct ResolvedExactGemm {
    matmul::v4::lt::ExactGemmBackend backend;
    const char* label{"cpu"};
};

/** Resolve LT ExactGemm providers only — no RC self-qual. */
ResolvedExactGemm ResolveExactGemmBackendForLT()
{
    ResolvedExactGemm resolved;

    // TPU and Trainium accelerate only LT's bounded-exact S8 GEMM lane, not
    // the full v4 digest dispatcher. Keep that narrower choice separate from
    // BTX_MATMUL_V4_BACKEND and explicit: an external provider must register,
    // attest native tensor execution, satisfy the t=24 proof gate, and pass
    // CPU byte-parity probes before either function pointer is exposed.
    if (const char* requested = std::getenv("BTX_MATMUL_LT_EXACT_BACKEND")) {
        const std::string exact_request{requested};
        const bool is_tpu = exact_request == "tpu";
        const bool is_trainium = exact_request == "trainium";
        bool available{false};
        if (is_tpu) {
            available = matmul_v4::tpu::IsTpuPjrtExactGemmAvailable();
            if (available) {
                resolved.backend.gemm_s8s8 = &matmul_v4::tpu::TryLaunchLtTpuGemmS8S8;
                resolved.backend.gemm_s32s8 = &matmul_v4::tpu::TryLaunchLtTpuGemmS32S8;
            }
        } else if (is_trainium) {
            available = matmul_v4::trainium::IsTrainiumExactGemmAvailable();
            if (available) {
                resolved.backend.gemm_s8s8 = &matmul_v4::trainium::TryLaunchLtTrainiumGemmS8S8;
                resolved.backend.gemm_s32s8 = &matmul_v4::trainium::TryLaunchLtTrainiumGemmS32S8;
            }
        }

        if (is_tpu || is_trainium) {
            static std::atomic_bool logged_cloud_exact{false};
            bool expected{false};
            if (logged_cloud_exact.compare_exchange_strong(expected, true)) {
                if (available) {
                    LogPrintf("MatMul-v4.4-LT exact GEMM provider: %s (native tensor path self-qualified; bounded S32xS8 uses four exact radix-256 tensor GEMMs)\n",
                              exact_request);
                } else {
                    LogPrintf("MatMul-v4.4-LT exact GEMM provider: CPU [WARNING: requested %s but its provider was not compiled, registered, attested, or self-qualified]\n",
                              exact_request);
                }
            }
            // Keep a stable label for RC gating / logs (string lives for process life
            // via getenv; copy into a static for the common tpu|trainium names).
            resolved.label = is_tpu ? "tpu" : "trainium";
            return resolved;
        }
    }

    switch (ResolveBackend()) {
    case Kind::CUDA:
        // LaunchGemm* prefers cuBLASLt IMMA then scalar device tiles.
        resolved.backend.gemm_s8s8 = &matmul_v4::cuda::LaunchGemmS8S8;
        resolved.backend.gemm_s32s8 = &matmul_v4::cuda::LaunchGemmS32S8;
        resolved.label = "cuda";
        break;
    case Kind::HIP:
        // LaunchGemm* prefers hipBLASLt/rocBLAS MFMA then device ALU tiles.
        resolved.backend.gemm_s8s8 = &matmul_v4::hip::LaunchGemmS8S8;
        resolved.backend.gemm_s32s8 = &matmul_v4::hip::LaunchGemmS32S8;
        resolved.label = "hip";
        break;
    case Kind::METAL:
        // LaunchGemm* prefers MPP TensorOps (ExactGemm self-qual) then ALU.
        resolved.backend.gemm_s8s8 = &matmul_v4::metal::LaunchGemmS8S8;
        resolved.backend.gemm_s32s8 = &matmul_v4::metal::LaunchGemmS32S8;
        resolved.label = "metal";
        break;
    case Kind::ASCEND:
        resolved.backend.gemm_s8s8 = &matmul_v4::ascend::TryLaunchLtCubeGemmS8S8;
        resolved.backend.gemm_s32s8 = &matmul_v4::ascend::TryLaunchLtCubeGemmS32S8;
        resolved.label = "ascend";
        break;
    case Kind::CPU:
        break;
    }
    return resolved;
}

/** RC fail-closed gate (R.5.2): device ExactGemm slots may mine RC only after
 *  ProbeRCSelfQual. On failure return an empty backend (CPU ExactGemmS8S8).
 *  Must only be applied on the RC resolve path — never on LT.
 *
 *  F5: keyed process-local cache so per-nonce miners never re-probe. Key =
 *  {provider_label, gemm_s8s8 address, epoch}. */
struct RCExactGemmCacheKey {
    std::string label;
    uintptr_t gemm_fn{0};
    int32_t epoch{-1};
    bool operator<(const RCExactGemmCacheKey& o) const
    {
        return std::tie(label, gemm_fn, epoch) < std::tie(o.label, o.gemm_fn, o.epoch);
    }
};

std::mutex g_rc_exact_gemm_cache_mu;
std::map<RCExactGemmCacheKey, matmul::v4::lt::ExactGemmBackend> g_rc_exact_gemm_cache;

matmul::v4::lt::ExactGemmBackend GateExactGemmWithRCSelfQualUncached(
    matmul::v4::lt::ExactGemmBackend backend, const char* provider_label)
{
    if (backend.gemm_s8s8 == nullptr) {
        return backend;
    }
    const matmul::v4::rc::RCSelfQualStatus st = matmul::v4::rc::ProbeRCSelfQual(backend);
    if (st.mining_accelerator_ok) {
        return backend;
    }
    static std::atomic_bool logged_rc_gate{false};
    bool expected{false};
    if (logged_rc_gate.compare_exchange_strong(expected, true)) {
        LogPrintf("MatMul-v4.4-RC ExactGemm: CPU [WARNING: provider=%s RC self-qual failed (%s); "
                  "clearing ExactGemmBackend]\n",
                  provider_label != nullptr ? provider_label : "device",
                  st.deficit_reason.empty() ? "unknown" : st.deficit_reason.c_str());
    }
    return matmul::v4::lt::ExactGemmBackend{};
}

} // namespace

matmul::v4::lt::ExactGemmBackend GateExactGemmWithRCSelfQualCached(
    matmul::v4::lt::ExactGemmBackend backend, const char* provider_label, int32_t epoch)
{
    RCExactGemmCacheKey key;
    key.label = provider_label != nullptr ? provider_label : "device";
    key.gemm_fn = reinterpret_cast<uintptr_t>(backend.gemm_s8s8);
    key.epoch = epoch;

    {
        std::lock_guard<std::mutex> lock(g_rc_exact_gemm_cache_mu);
        const auto it = g_rc_exact_gemm_cache.find(key);
        if (it != g_rc_exact_gemm_cache.end()) {
            return it->second;
        }
    }

    const matmul::v4::lt::ExactGemmBackend gated =
        GateExactGemmWithRCSelfQualUncached(std::move(backend), provider_label);

    std::lock_guard<std::mutex> lock(g_rc_exact_gemm_cache_mu);
    const auto [it, inserted] = g_rc_exact_gemm_cache.emplace(key, gated);
    (void)inserted;
    return it->second;
}

void ResetRCExactGemmResolveCacheForTest()
{
    std::lock_guard<std::mutex> lock(g_rc_exact_gemm_cache_mu);
    g_rc_exact_gemm_cache.clear();
    matmul::v4::rc::ResetRCSelfQualCacheForTest();
}

matmul::v4::lt::ExactGemmBackend MakeResolvedExactGemmBackend()
{
    // LT mining path: return the LT-qualified ExactGemm inject unchanged.
    // RC self-qual must not clear or replace this backend.
    return ResolveExactGemmBackendForLT().backend;
}

matmul::v4::lt::ExactGemmBackend MakeResolvedExactGemmBackendForRC()
{
    const ResolvedExactGemm resolved = ResolveExactGemmBackendForLT();
    // Arch/provider identity is the resolve label (cuda/hip/metal/cpu/…).
    return GateExactGemmWithRCSelfQualCached(resolved.backend, resolved.label, /*epoch=*/-1);
}

matmul::v4::lt::ExactMxProjectionBackend MakeResolvedExactMxProjectionBackend()
{
    matmul::v4::lt::ExactMxProjectionBackend backend;

    // TPU/Trainium ExactGemm providers do not expose an MX projection inject;
    // leave project_right null so ComputeProjectedRightMxDispatched uses the
    // CPU oracle (same fail-closed contract as an unset GEMM slot).
    if (const char* requested = std::getenv("BTX_MATMUL_LT_EXACT_BACKEND")) {
        const std::string exact_request{requested};
        if (exact_request == "tpu" || exact_request == "trainium") {
            return backend;
        }
    }

    switch (ResolveBackend()) {
    case Kind::CUDA:
        backend.project_right = &matmul_v4::cuda::LaunchProjectedRightMx;
        break;
    case Kind::HIP:
        backend.project_right = &matmul_v4::hip::LaunchProjectedRightMx;
        break;
    case Kind::METAL:
        backend = matmul_v4::metal::MakeMetalExactMxProjectionBackend();
        break;
    case Kind::ASCEND:
        backend.project_right = &matmul_v4::ascend::TryLaunchLtCubeMxProjectRight;
        break;
    case Kind::CPU:
        break;
    }
    return backend;
}

bool ComputeDigestDispatched(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                             uint256& digest_out, std::vector<unsigned char>& payload_out)
{
    g_requests.fetch_add(1, std::memory_order_relaxed);

    const Kind backend = ResolveBackend();
    if (backend == Kind::CPU) {
        return matmul_v4::ComputeDigest(header, n, rounds, digest_out, payload_out);
    }

    const AccelFn fn = DeviceFnFor(backend);

    uint256 accel_digest;
    std::vector<unsigned char> accel_payload;
    bool device_ok = false;
    std::string error;
    try {
        device_ok = (fn != nullptr) &&
            fn(header, n, rounds, accel_digest, accel_payload);
        if (!device_ok) {
            error = "device_returned_false_or_unavailable";
        }
    } catch (const std::exception& e) {
        device_ok = false;
        error = std::string("device_exception:") + e.what();
    } catch (...) {
        device_ok = false;
        error = "device_unknown_exception";
    }

    if (device_ok) {
        // HARD REQUIREMENT: never accept a device digest without verifying it
        // reproduces the CPU reference. matmul_v4::VerifySketch (O(n^2))
        // regenerates the honest operands A,B,U,V on the host, recomputes the
        // digest from the device payload, and runs the sketch-Freivalds check
        // over q = 2^61-1; it returns true iff the payload commits to the true
        // product A*B AND the device digest equals H(sigma || payload). We stage
        // the device digest into a header copy so VerifySketch's digest-equality
        // gate checks the device's own output. A wrong GPU digest fails here and
        // is discarded before it can ever be mined into a block.
        CBlockHeader verify_header = header;
        verify_header.matmul_digest = accel_digest;
        uint256 verify_digest;
        bool verified = false;
        try {
            verified = matmul_v4::VerifySketch(verify_header, n, rounds, accel_payload, verify_digest);
        } catch (const std::exception& e) {
            verified = false;
            error = std::string("verify_exception:") + e.what();
        } catch (...) {
            verified = false;
            error = "verify_unknown_exception";
        }

        if (verified && verify_digest == accel_digest) {
            digest_out = accel_digest;
            payload_out = std::move(accel_payload);
            RecordOk(backend);
            return true;
        }

        // Device produced output that does NOT reproduce the CPU reference.
        if (error.empty()) {
            error = "digest_mismatch_failed_cpu_verification";
        }
        RecordMismatch(backend);
    }

    // Fall back to the pure-integer CPU reference on any device error or
    // verification mismatch. This is the byte-exact consensus path.
    RecordFallback(backend, error);
    return matmul_v4::ComputeDigest(header, n, rounds, digest_out, payload_out);
}

bool ComputeDigestsBatchedDispatched(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                     std::vector<uint256>& digests_out,
                                     std::vector<std::vector<unsigned char>>& payloads_out)
{
    g_batch_requests.fetch_add(1, std::memory_order_relaxed);

    if (headers.empty()) {
        digests_out.clear();
        payloads_out.clear();
        return false;
    }

    const Kind backend = ResolveBackend();
    if (backend == Kind::CPU) {
        return ComputeBatchCpuReference(headers, n, rounds, digests_out, payloads_out);
    }

    const BatchAccelFn fn = BatchDeviceFnFor(backend);

    std::vector<uint256> accel_digests;
    std::vector<std::vector<unsigned char>> accel_payloads;
    bool device_ok = false;
    std::string error;
    try {
        device_ok = (fn != nullptr) &&
            fn(headers, n, rounds, accel_digests, accel_payloads);
        if (!device_ok) {
            error = "device_returned_false_or_unavailable";
        } else if (accel_digests.size() != headers.size() ||
                   accel_payloads.size() != headers.size()) {
            device_ok = false;
            error = "device_returned_wrong_window_size";
        }
    } catch (const std::exception& e) {
        device_ok = false;
        error = std::string("device_exception:") + e.what();
    } catch (...) {
        device_ok = false;
        error = "device_unknown_exception";
    }

    if (device_ok) {
        // HARD REQUIREMENT (same contract as the per-nonce path, applied to the
        // whole window): verify EVERY returned (digest,payload) reproduces the
        // CPU reference via matmul_v4::VerifySketch. A single failure anywhere
        // in the window discards the ENTIRE device result -- we never mine a
        // partially-trusted window -- and the whole window is recomputed on the
        // CPU below. A wrong GPU digest can therefore never win a block.
        bool all_verified = true;
        for (size_t i = 0; i < headers.size(); ++i) {
            CBlockHeader verify_header = headers[i];
            verify_header.matmul_digest = accel_digests[i];
            uint256 verify_digest;
            bool verified = false;
            try {
                verified = matmul_v4::VerifySketch(verify_header, n, rounds, accel_payloads[i], verify_digest);
            } catch (const std::exception& e) {
                verified = false;
                error = std::string("verify_exception:") + e.what();
            } catch (...) {
                verified = false;
                error = "verify_unknown_exception";
            }
            if (!(verified && verify_digest == accel_digests[i])) {
                all_verified = false;
                if (error.empty()) {
                    error = "digest_mismatch_failed_cpu_verification";
                }
                break;
            }
        }

        if (all_verified) {
            digests_out = std::move(accel_digests);
            payloads_out = std::move(accel_payloads);
            RecordBatchOk(backend);
            return true;
        }

        RecordBatchMismatch(backend);
    }

    RecordBatchFallback(backend, error);
    return ComputeBatchCpuReference(headers, n, rounds, digests_out, payloads_out);
}

bool ComputeDigestsBMX4CDispatched(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                   const uint256& win_target,
                                   std::vector<uint256>& digests_out,
                                   std::vector<std::vector<unsigned char>>& payloads_out)
{
    g_batch_requests.fetch_add(1, std::memory_order_relaxed);

    if (headers.empty()) {
        digests_out.clear();
        payloads_out.clear();
        return false;
    }

    const Kind backend = ResolveBackend();
    if (backend == Kind::CPU) {
        return ComputeBatchCpuReferenceBMX4C(headers, n, rounds, digests_out, payloads_out);
    }

    const BatchAccelFn fn = BMX4CDeviceFnFor(backend);

    std::vector<uint256> accel_digests;
    std::vector<std::vector<unsigned char>> accel_payloads;
    bool device_ok = false;
    std::string error;
    try {
        device_ok = (fn != nullptr) &&
            fn(headers, n, rounds, accel_digests, accel_payloads);
        if (!device_ok) {
            error = "device_returned_false_or_unavailable";
        } else if (accel_digests.size() != headers.size() ||
                   accel_payloads.size() != headers.size()) {
            device_ok = false;
            error = "device_returned_wrong_window_size";
        }
    } catch (const std::exception& e) {
        device_ok = false;
        error = std::string("device_exception:") + e.what();
    } catch (...) {
        device_ok = false;
        error = "device_unknown_exception";
    }

    if (device_ok) {
        // HARD REQUIREMENT (same contract as the ENC-S8 batched path): every
        // returned (digest,payload) whose digest is a POTENTIAL WINNER
        // (digest <= win_target) must reproduce the ENC-BMX4C CPU reference via
        // matmul::v4::bmx4::VerifySketchBMX4C (which re-derives the honest
        // M11+E8M0 operands on the host, recomputes the digest, and runs the
        // UNCHANGED sketch-Freivalds check over q = 2^61-1). A single failure
        // among the potential winners discards the ENTIRE device window; it is
        // recomputed on the CPU below. A wrong device digest can therefore never
        // win a block.
        //
        // Audit P1-4: LOSING nonces (digest > win_target) are NOT Freivalds-
        // verified here. A losing nonce can never be sealed no matter whether its
        // device digest is right or wrong, so an 8 MiB verify on it is pure wasted
        // CPU -- and at a Q=64 window at most one nonce can win, so verifying all
        // 64 paid ~64x the cost for zero safety gain. The winning nonce (if any)
        // is additionally re-derived through the single-nonce reference and
        // resealed by the caller, so winners stay doubly protected.
        const arith_uint256 win_target_arith = UintToArith256(win_target);
        bool all_verified = true;
        for (size_t i = 0; i < headers.size(); ++i) {
            if (UintToArith256(accel_digests[i]) > win_target_arith) {
                continue; // losing nonce: cannot win, skip the 8 MiB verify
            }
            CBlockHeader verify_header = headers[i];
            verify_header.matmul_digest = accel_digests[i];
            uint256 verify_digest;
            bool verified = false;
            try {
                verified = matmul::v4::bmx4::VerifySketchBMX4C(verify_header, n, rounds, accel_payloads[i], verify_digest);
            } catch (const std::exception& e) {
                verified = false;
                error = std::string("verify_exception:") + e.what();
            } catch (...) {
                verified = false;
                error = "verify_unknown_exception";
            }
            if (!(verified && verify_digest == accel_digests[i])) {
                all_verified = false;
                if (error.empty()) {
                    error = "digest_mismatch_failed_cpu_verification";
                }
                break;
            }
        }

        if (all_verified) {
            digests_out = std::move(accel_digests);
            payloads_out = std::move(accel_payloads);
            RecordBatchOk(backend);
            return true;
        }

        RecordBatchMismatch(backend);
    }

    RecordBatchFallback(backend, error);
    return ComputeBatchCpuReferenceBMX4C(headers, n, rounds, digests_out, payloads_out);
}

bool ComputeDigestsBMX4CLTDispatched(const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t rounds,
                                     const uint256& win_target,
                                     std::vector<uint256>& digests_out,
                                     std::vector<std::vector<unsigned char>>& payloads_out)
{
    g_batch_requests.fetch_add(1, std::memory_order_relaxed);

    if (headers.empty()) {
        digests_out.clear();
        payloads_out.clear();
        return false;
    }

    const Kind backend = ResolveBackend();
    if (backend == Kind::CPU) {
        const bool ok = ComputeBatchCpuReferenceBMX4CLT(
            headers, n, rounds, digests_out, payloads_out);
        if (ok) DropLosingPayloadsBMX4CLT(win_target, digests_out, payloads_out);
        return ok;
    }

    std::vector<uint256> accel_digests;
    std::vector<std::vector<unsigned char>> accel_payloads;
    bool device_ok = false;
    std::string error;
    try {
        device_ok = TryDeviceDigestsBMX4CLT(
            backend, headers, n, win_target, accel_digests, accel_payloads);
        if (!device_ok) {
            error = "device_returned_false_or_unavailable";
        } else if (accel_digests.size() != headers.size() ||
                   accel_payloads.size() != headers.size()) {
            device_ok = false;
            error = "device_returned_wrong_window_size";
        }
    } catch (const std::exception& e) {
        device_ok = false;
        error = std::string("device_exception:") + e.what();
    } catch (...) {
        device_ok = false;
        error = "device_unknown_exception";
    }

    if (device_ok) {
        const arith_uint256 win_target_arith = UintToArith256(win_target);
        bool all_verified = true;
        for (size_t i = 0; i < headers.size(); ++i) {
            if (UintToArith256(accel_digests[i]) > win_target_arith) {
                continue;
            }
            CBlockHeader verify_header = headers[i];
            verify_header.matmul_digest = accel_digests[i];
            uint256 verify_digest;
            bool verified = false;
            try {
                verified = matmul::v4::lt::VerifySketchBMX4CLT(
                    verify_header, n, rounds, accel_payloads[i], verify_digest);
            } catch (const std::exception& e) {
                verified = false;
                error = std::string("verify_exception:") + e.what();
            } catch (...) {
                verified = false;
                error = "verify_unknown_exception";
            }
            if (!(verified && verify_digest == accel_digests[i])) {
                all_verified = false;
                if (error.empty()) {
                    error = "digest_mismatch_failed_cpu_verification";
                }
                break;
            }
        }

        if (all_verified) {
            digests_out = std::move(accel_digests);
            payloads_out = std::move(accel_payloads);
            RecordBatchOk(backend);
            return true;
        }

        RecordBatchMismatch(backend);
    }

    RecordBatchFallback(backend, error);
    const bool ok = ComputeBatchCpuReferenceBMX4CLT(
        headers, n, rounds, digests_out, payloads_out);
    if (ok) DropLosingPayloadsBMX4CLT(win_target, digests_out, payloads_out);
    return ok;
}

Stats ProbeStats()
{
    Stats stats;
    stats.requests = g_requests.load(std::memory_order_relaxed);
    stats.cuda_ok = g_cuda_ok.load(std::memory_order_relaxed);
    stats.cuda_mismatch = g_cuda_mismatch.load(std::memory_order_relaxed);
    stats.cuda_fallback = g_cuda_fallback.load(std::memory_order_relaxed);
    stats.metal_ok = g_metal_ok.load(std::memory_order_relaxed);
    stats.metal_mismatch = g_metal_mismatch.load(std::memory_order_relaxed);
    stats.metal_fallback = g_metal_fallback.load(std::memory_order_relaxed);
    stats.hip_ok = g_hip_ok.load(std::memory_order_relaxed);
    stats.hip_mismatch = g_hip_mismatch.load(std::memory_order_relaxed);
    stats.hip_fallback = g_hip_fallback.load(std::memory_order_relaxed);
    stats.ascend_ok = g_ascend_ok.load(std::memory_order_relaxed);
    stats.ascend_mismatch = g_ascend_mismatch.load(std::memory_order_relaxed);
    stats.ascend_fallback = g_ascend_fallback.load(std::memory_order_relaxed);
    stats.batch_requests = g_batch_requests.load(std::memory_order_relaxed);
    stats.cuda_batch_ok = g_cuda_batch_ok.load(std::memory_order_relaxed);
    stats.cuda_batch_mismatch = g_cuda_batch_mismatch.load(std::memory_order_relaxed);
    stats.cuda_batch_fallback = g_cuda_batch_fallback.load(std::memory_order_relaxed);
    stats.metal_batch_ok = g_metal_batch_ok.load(std::memory_order_relaxed);
    stats.metal_batch_mismatch = g_metal_batch_mismatch.load(std::memory_order_relaxed);
    stats.metal_batch_fallback = g_metal_batch_fallback.load(std::memory_order_relaxed);
    stats.hip_batch_ok = g_hip_batch_ok.load(std::memory_order_relaxed);
    stats.hip_batch_mismatch = g_hip_batch_mismatch.load(std::memory_order_relaxed);
    stats.hip_batch_fallback = g_hip_batch_fallback.load(std::memory_order_relaxed);
    stats.ascend_batch_ok = g_ascend_batch_ok.load(std::memory_order_relaxed);
    stats.ascend_batch_mismatch = g_ascend_batch_mismatch.load(std::memory_order_relaxed);
    stats.ascend_batch_fallback = g_ascend_batch_fallback.load(std::memory_order_relaxed);
    return stats;
}

void ResetStats()
{
    g_requests.store(0, std::memory_order_relaxed);
    g_cuda_ok.store(0, std::memory_order_relaxed);
    g_cuda_mismatch.store(0, std::memory_order_relaxed);
    g_cuda_fallback.store(0, std::memory_order_relaxed);
    g_metal_ok.store(0, std::memory_order_relaxed);
    g_metal_mismatch.store(0, std::memory_order_relaxed);
    g_metal_fallback.store(0, std::memory_order_relaxed);
    g_hip_ok.store(0, std::memory_order_relaxed);
    g_hip_mismatch.store(0, std::memory_order_relaxed);
    g_hip_fallback.store(0, std::memory_order_relaxed);
    g_ascend_ok.store(0, std::memory_order_relaxed);
    g_ascend_mismatch.store(0, std::memory_order_relaxed);
    g_ascend_fallback.store(0, std::memory_order_relaxed);
    g_logged_cuda_fallback.store(false, std::memory_order_relaxed);
    g_logged_metal_fallback.store(false, std::memory_order_relaxed);
    g_logged_hip_fallback.store(false, std::memory_order_relaxed);
    g_logged_ascend_fallback.store(false, std::memory_order_relaxed);
    g_batch_requests.store(0, std::memory_order_relaxed);
    g_cuda_batch_ok.store(0, std::memory_order_relaxed);
    g_cuda_batch_mismatch.store(0, std::memory_order_relaxed);
    g_cuda_batch_fallback.store(0, std::memory_order_relaxed);
    g_metal_batch_ok.store(0, std::memory_order_relaxed);
    g_metal_batch_mismatch.store(0, std::memory_order_relaxed);
    g_metal_batch_fallback.store(0, std::memory_order_relaxed);
    g_hip_batch_ok.store(0, std::memory_order_relaxed);
    g_hip_batch_mismatch.store(0, std::memory_order_relaxed);
    g_hip_batch_fallback.store(0, std::memory_order_relaxed);
    g_ascend_batch_ok.store(0, std::memory_order_relaxed);
    g_ascend_batch_mismatch.store(0, std::memory_order_relaxed);
    g_ascend_batch_fallback.store(0, std::memory_order_relaxed);
    g_logged_cuda_batch_fallback.store(false, std::memory_order_relaxed);
    g_logged_metal_batch_fallback.store(false, std::memory_order_relaxed);
    g_logged_hip_batch_fallback.store(false, std::memory_order_relaxed);
    g_logged_ascend_batch_fallback.store(false, std::memory_order_relaxed);
}

} // namespace matmul_v4::accel
