// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/matmul_v4_lt_mx_exact.h>

#include <cassert>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <limits>

namespace matmul::v4::lt {
namespace {

[[nodiscard]] bool RunS8S8(const ExactGemmBackend& gemm, const std::vector<int8_t>& L,
                           const std::vector<int8_t>& R, uint32_t rows, uint32_t inner,
                           uint32_t cols, std::vector<int32_t>& out)
{
    if (gemm.gemm_s8s8 != nullptr) {
        return gemm.gemm_s8s8(L, R, rows, inner, cols, out);
    }
    out = ExactGemmS8S8(L, R, rows, inner, cols);
    return out.size() == static_cast<size_t>(rows) * cols;
}

} // namespace

bool LtMxProjectionFitsFloat32ExactInteger(uint32_t n, uint32_t /*m*/)
{
    // Magnitude depends only on contraction length n. Reject empty / overflow.
    if (n == 0) return false;
    const int64_t bound = LtMxProjectionAbsBound(n);
    if (bound / static_cast<int64_t>(n) != static_cast<int64_t>(kLtMxProjPerMac)) {
        return false; // n * 288 overflowed int64
    }
    return bound < kLtMxFloat32ExactIntegerCeil;
}

std::vector<int32_t> ComputeProjectedRightMxScalePartitionedGemmLT(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m, const ExactGemmBackend& gemm)
{
    assert(n % kMatExpandMxBlockLen == 0);
    const uint32_t nblk = n / kMatExpandMxBlockLen;
    assert(mu.size() == static_cast<size_t>(n) * n);
    assert(scales.size() == static_cast<size_t>(n) * nblk);
    assert(V.size() == static_cast<size_t>(n) * m);

    std::vector<int32_t> Q(static_cast<size_t>(n) * m, 0);

    // Four exact partitions (e = 0..3). For each e, build mu_e (n×n) with
    // mantissas only where the 32-col block scale equals e (else 0), then
    // Q += ExactGemmS8S8(mu_e, V) << e. Algebraically identical to the
    // per-block loop in ComputeProjectedRightMxBlockScaleLT.
    for (uint8_t e = 0; e < 4; ++e) {
        std::vector<int8_t> mu_e(static_cast<size_t>(n) * n, 0);
        bool any = false;
        for (uint32_t i = 0; i < n; ++i) {
            for (uint32_t bj = 0; bj < nblk; ++bj) {
                if (scales[static_cast<size_t>(i) * nblk + bj] != e) continue;
                const size_t base =
                    static_cast<size_t>(i) * n + static_cast<size_t>(bj) * kMatExpandMxBlockLen;
                for (uint32_t t = 0; t < kMatExpandMxBlockLen; ++t) {
                    const int8_t v = mu[base + t];
                    if (v != 0) {
                        mu_e[base + t] = v;
                        any = true;
                    }
                }
            }
        }
        if (!any) continue;

        std::vector<int32_t> part;
        if (!RunS8S8(gemm, mu_e, V, n, n, m, part) ||
            part.size() != static_cast<size_t>(n) * m) {
            // Structural failure → empty result signals caller to fail closed.
            return {};
        }
        const int32_t shift = int32_t{1} << e;
        for (size_t idx = 0; idx < part.size(); ++idx) {
            Q[idx] += part[idx] * shift;
        }
    }
    return Q;
}

bool MxProjectionMatchesCpuOracle(const std::vector<int8_t>& mu,
                                  const std::vector<uint8_t>& scales,
                                  const std::vector<int8_t>& V, uint32_t n, uint32_t m,
                                  const std::vector<int32_t>& got)
{
    const std::vector<int32_t> gold = ComputeProjectedRightMxBlockScaleLT(mu, scales, V, n, m);
    if (got.size() != gold.size()) return false;
    return std::memcmp(got.data(), gold.data(), gold.size() * sizeof(int32_t)) == 0;
}

std::vector<int32_t> ComputeProjectedRightMxDispatched(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m,
    const ExactMxProjectionBackend& backend, MxLaneProvenance* provenance)
{
    MxLaneProvenance local{};
    if (backend.project_right != nullptr) {
        std::vector<int32_t> out;
        MxLaneProvenance device_prov{};
        if (backend.project_right(mu, scales, V, n, m, out, &device_prov) &&
            MxProjectionMatchesCpuOracle(mu, scales, V, n, m, out)) {
            if (provenance) *provenance = device_prov;
            return out;
        }
        // Device mismatch or failure: never trust unqualified native flags.
        local = {};
    }
    auto cpu = ComputeProjectedRightMxBlockScaleLT(mu, scales, V, n, m);
    local.exact_mx_scale_partitioned = true;
    if (provenance) *provenance = local;
    return cpu;
}

std::vector<int32_t> SimulateProjectedRightMxFloat32AccumulateLT(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m)
{
    assert(n % kMatExpandMxBlockLen == 0);
    const uint32_t nblk = n / kMatExpandMxBlockLen;
    assert(mu.size() == static_cast<size_t>(n) * n);
    assert(scales.size() == static_cast<size_t>(n) * nblk);
    assert(V.size() == static_cast<size_t>(n) * m);

    std::vector<int32_t> Q(static_cast<size_t>(n) * m, 0);
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t c = 0; c < m; ++c) {
            float acc = 0.0f;
            for (uint32_t bj = 0; bj < nblk; ++bj) {
                const uint8_t e = scales[static_cast<size_t>(i) * nblk + bj];
                const float scale = static_cast<float>(int32_t{1} << e);
                const size_t mu_base =
                    static_cast<size_t>(i) * n + static_cast<size_t>(bj) * kMatExpandMxBlockLen;
                for (uint32_t t = 0; t < kMatExpandMxBlockLen; ++t) {
                    const uint32_t k = bj * kMatExpandMxBlockLen + t;
                    const float prod = static_cast<float>(mu[mu_base + t]) * scale *
                                       static_cast<float>(V[static_cast<size_t>(k) * m + c]);
                    acc += prod;
                }
            }
            // Inside the proven window every acc is an exact integer; cast must
            // not require rounding. Fail closed to empty on non-finite / non-int.
            if (!std::isfinite(acc)) return {};
            const float rounded = std::nearbyintf(acc);
            if (rounded != acc) return {};
            if (rounded > static_cast<float>(std::numeric_limits<int32_t>::max()) ||
                rounded < static_cast<float>(std::numeric_limits<int32_t>::min())) {
                return {};
            }
            Q[static_cast<size_t>(i) * m + c] = static_cast<int32_t>(rounded);
        }
    }
    return Q;
}

bool LtEnvFlagEnabled(const char* name)
{
    if (name == nullptr || name[0] == '\0') return false;
    const char* value = std::getenv(name);
    if (value == nullptr || value[0] == '\0') return false;
    if (std::strcmp(value, "1") == 0) return true;
    // Accept common truthy spellings without pulling locale-heavy helpers.
    if ((value[0] == 't' || value[0] == 'T') &&
        (value[1] == 'r' || value[1] == 'R') &&
        (value[2] == 'u' || value[2] == 'U') &&
        (value[3] == 'e' || value[3] == 'E') && value[4] == '\0') {
        return true;
    }
    if ((value[0] == 'y' || value[0] == 'Y') &&
        (value[1] == 'e' || value[1] == 'E') &&
        (value[2] == 's' || value[2] == 'S') && value[3] == '\0') {
        return true;
    }
    if ((value[0] == 'o' || value[0] == 'O') &&
        (value[1] == 'n' || value[1] == 'N') && value[2] == '\0') {
        return true;
    }
    return false;
}

bool AllowLtExactMxFallback()
{
    return LtEnvFlagEnabled("BTX_MATMUL_V4_LT_ALLOW_EXACT_MX_FALLBACK");
}

} // namespace matmul::v4::lt
