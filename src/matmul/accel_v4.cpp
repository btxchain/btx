// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/accel_v4.h>

#include <matmul/backend_capabilities.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_bmx4_batch.h>
#include <matmul/pow_v4.h>
#include <primitives/block.h>
#include <logging.h>

#include <atomic>
#include <cstdlib>
#include <exception>
#include <mutex>
#include <string>

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

std::atomic_bool g_logged_cuda_fallback{false};
std::atomic_bool g_logged_metal_fallback{false};
std::atomic_bool g_logged_hip_fallback{false};

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

std::atomic_bool g_logged_cuda_batch_fallback{false};
std::atomic_bool g_logged_metal_batch_fallback{false};
std::atomic_bool g_logged_hip_batch_fallback{false};

char ToLowerAscii(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return static_cast<char>(c + ('a' - 'A'));
    }
    return c;
}

std::string ToLowerAsciiString(std::string value)
{
    for (char& c : value) {
        c = ToLowerAscii(c);
    }
    return value;
}

std::string DefaultBackendRequest()
{
#if defined(__APPLE__)
    return "metal";
#else
    return "cpu";
#endif
}

// Parse BTX_MATMUL_V4_BACKEND into a Kind. Unknown tokens map to CPU with
// `known=false` so the resolver can log the fallback reason.
Kind ParseKind(const std::string& requested, bool& known)
{
    const std::string normalized = ToLowerAsciiString(requested);
    known = true;
    if (normalized == "cpu") return Kind::CPU;
    if (normalized == "cuda") return Kind::CUDA;
    if (normalized == "metal" || normalized == "mlx") return Kind::METAL;
    if (normalized == "hip" || normalized == "rocm") return Kind::HIP;
    known = false;
    return Kind::CPU;
}

// Availability of an accelerated backend. CUDA/METAL reuse the v3 capability
// probe (compiled-in AND a usable device). HIP has no v3 capability probe, so
// it is treated as "available" whenever requested -- if only the weak stub is
// linked, its ComputeDigestAccel returns false and the dispatcher falls back to
// CPU on the very first nonce (correct, just no speedup).
bool IsAcceleratedBackendAvailable(Kind kind, std::string& reason)
{
    switch (kind) {
    case Kind::CUDA: {
        const auto cap = matmul::backend::CapabilityFor(matmul::backend::Kind::CUDA);
        reason = cap.reason;
        return cap.available;
    }
    case Kind::METAL: {
        const auto cap = matmul::backend::CapabilityFor(matmul::backend::Kind::METAL);
        reason = cap.reason;
        return cap.available;
    }
    case Kind::HIP:
        reason = "hip_selected_by_request";
        return true;
    case Kind::CPU:
        reason = "always_available";
        return true;
    }
    reason = "unknown_backend";
    return false;
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
    case Kind::CPU: break;
    }
}

void RecordMismatch(Kind kind)
{
    switch (kind) {
    case Kind::CUDA: g_cuda_mismatch.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::METAL: g_metal_mismatch.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::HIP: g_hip_mismatch.fetch_add(1, std::memory_order_relaxed); break;
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
    case Kind::CPU: break;
    }
}

void RecordBatchMismatch(Kind kind)
{
    switch (kind) {
    case Kind::CUDA: g_cuda_batch_mismatch.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::METAL: g_metal_batch_mismatch.fetch_add(1, std::memory_order_relaxed); break;
    case Kind::HIP: g_hip_batch_mismatch.fetch_add(1, std::memory_order_relaxed); break;
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

} // namespace

std::string ToString(Kind kind)
{
    switch (kind) {
    case Kind::CPU: return "cpu";
    case Kind::CUDA: return "cuda";
    case Kind::METAL: return "metal";
    case Kind::HIP: return "hip";
    }
    return "cpu";
}

Kind ResolveBackend()
{
    const char* const env = std::getenv("BTX_MATMUL_V4_BACKEND");
    const std::string requested = (env != nullptr && env[0] != '\0')
        ? std::string{env}
        : DefaultBackendRequest();

    bool known{false};
    const Kind requested_kind = ParseKind(requested, known);

    Kind active = Kind::CPU;
    std::string reason;
    if (!known) {
        reason = "unknown_backend_fallback_to_cpu:" + requested;
    } else if (requested_kind == Kind::CPU) {
        active = Kind::CPU;
        reason = "requested_cpu";
    } else {
        std::string avail_reason;
        if (IsAcceleratedBackendAvailable(requested_kind, avail_reason)) {
            active = requested_kind;
            reason = "requested_backend_available:" + avail_reason;
        } else {
            reason = ToString(requested_kind) + "_unavailable_fallback_to_cpu:" + avail_reason;
        }
    }

    // Emit one clear line describing the RESOLVED v4 mining backend the first
    // time this is called (mirrors v3 ResolveMiningBackendFromEnvironment), so a
    // silent CPU fallback from an unavailable GPU request can never hide.
    static std::atomic_bool logged_resolved{false};
    bool expected{false};
    if (logged_resolved.compare_exchange_strong(expected, true)) {
        if (active == requested_kind && known) {
            LogPrintf("MatMul-v4 mining backend: %s (requested=%s, %s)\n",
                      ToString(active), requested, reason);
        } else {
            LogPrintf("MatMul-v4 mining backend: %s [WARNING: requested %s but it is "
                      "unavailable -> %s]\n",
                      ToString(active), requested, reason);
        }
    }

    return active;
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
        // HARD REQUIREMENT (same contract as the ENC-S8 batched path): verify
        // EVERY returned (digest,payload) reproduces the ENC-BMX4C CPU reference
        // via matmul::v4::bmx4::VerifySketchBMX4C (which re-derives the honest
        // M11+E8M0 operands on the host, recomputes the digest, and runs the
        // UNCHANGED sketch-Freivalds check over q = 2^61-1). A single failure
        // anywhere discards the ENTIRE device window; it is recomputed on the
        // CPU below. A wrong device digest can therefore never win a block.
        bool all_verified = true;
        for (size_t i = 0; i < headers.size(); ++i) {
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
    g_logged_cuda_fallback.store(false, std::memory_order_relaxed);
    g_logged_metal_fallback.store(false, std::memory_order_relaxed);
    g_logged_hip_fallback.store(false, std::memory_order_relaxed);
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
    g_logged_cuda_batch_fallback.store(false, std::memory_order_relaxed);
    g_logged_metal_batch_fallback.store(false, std::memory_order_relaxed);
    g_logged_hip_batch_fallback.store(false, std::memory_order_relaxed);
}

} // namespace matmul_v4::accel
