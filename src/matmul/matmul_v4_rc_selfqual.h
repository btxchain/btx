// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_SELFQUAL_H
#define BTX_MATMUL_MATMUL_V4_RC_SELFQUAL_H

#include <matmul/matmul_v4_lt.h>

#include <cstdint>
#include <optional>
#include <string>

namespace Consensus {
struct Params;
}

// ENC_RC ExactGemm self-qualification (R.5.2 / §R.7 §4) — fail-closed.
// A mining ExactGemmBackend may serve RC only after ProbeRCSelfQual reports
// mining_accelerator_ok. native_mxfp4 / native_fp8 stay false until a device
// RC MX path exists and qualifies separately. When height+params are supplied,
// episode probes use ConsensusRCEpisodeParamsForHeight (live epoch shape).

namespace matmul::v4::rc {

struct RCSelfQualStatus {
    bool cpu_oracle_ok{true};
    bool exact_gemm_backend_ok{false};
    bool native_mxfp4_qualified{false}; // always false until device RC MX path exists
    bool native_fp8_qualified{false};
    bool mining_accelerator_ok{false}; // true only if exact_gemm_backend_ok
    std::string deficit_reason;
};

/** Probe ExactGemmBackend against the RC CPU oracle.
 *  Without height/params: toy (<2^24 stages) + medium (>2^24 wgrad) vectors.
 *  With height+params: qualify at ConsensusRCEpisodeParamsForHeight live dims,
 *  plus a scaled medium contraction covering the >2^24 regime at that epoch.
 *  Fail-closed: any mismatch clears mining_accelerator_ok and native_* flags. */
[[nodiscard]] RCSelfQualStatus ProbeRCSelfQual(
    const matmul::v4::lt::ExactGemmBackend& backend,
    std::optional<int32_t> height = std::nullopt,
    const Consensus::Params* params_ref = nullptr);

/** Log one-line RC self-qual status for an empty (CPU) probe. */
void DiagnoseRCSelfQualOnce();

/** True iff ProbeRCSelfQual(backend).mining_accelerator_ok (cached process-wide
 *  after a successful probe of this backend signature). */
[[nodiscard]] bool RCAcceleratorAdmissible(const matmul::v4::lt::ExactGemmBackend& backend);

/** Process-wide latch set by ProbeRCSelfQual / RCAcceleratorAdmissible.
 *  Used by backend ResolveBackend fail-closed gate (§N.3-v style). */
[[nodiscard]] bool HasPassedRCSelfQual();

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_SELFQUAL_H
