// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_PEAK_READY_H
#define BTX_MATMUL_MATMUL_V4_RC_PEAK_READY_H

#include <cstdint>
#include <string>

// Derived peak_ready — never set manually by callers.
// cuda_episode_ready / provenance.peak_ready MUST come from DeriveRCPeakReady;
// never equate `compiled == ready`.

namespace matmul::v4::rc {

struct RCPeakReadyInputs {
    bool v3_config_selected{false};
    bool production_dimensions{false};
    bool full_page_schedule{false};      // 1536 pages / 24 per slot
    bool real_m128_workload{false};
    bool canonical_packed_bank{false};
    bool native_provider_linked{false};
    bool arch_backend_selected{false}; // SM120_MMA or SM100 separate latch
    bool exactness_selfqual_ok{false};
    bool bank_genuinely_resident{false};
    bool native_tensor_executed{false};
    bool full_device_pipeline{false}; // perm/mix/exchange/Extract/digest on device
    bool no_per_barrier_host_sync{false};
    bool no_cpu_fallback{false};
    bool no_dense_int8_as_native{false};
    bool no_scalar_cuda_as_native{false};
    bool device_event_timing{false};
    bool cpu_gpu_byte_exact{false};
    bool production_provenance_recorded{false};
    bool corruption_gate_ok{false};
    bool production_readiness_tests_pass{false};
};

struct RCPeakReadyStatus {
    bool peak_ready{false};
    bool compiled{false};
    bool linked{false};
    bool capable{false};
    bool attempted{false};
    bool self_qualified{false};
    bool resident{false};
    bool full_pipeline_device{false};
    bool device_timed{false};
    bool production_qualified{false};
    std::string deficit;
};

[[nodiscard]] inline RCPeakReadyStatus DeriveRCPeakReady(const RCPeakReadyInputs& in)
{
    RCPeakReadyStatus st;
    st.compiled = in.v3_config_selected;
    st.linked = in.native_provider_linked;
    st.capable = in.arch_backend_selected;
    st.attempted = in.native_tensor_executed || in.exactness_selfqual_ok;
    st.self_qualified = in.exactness_selfqual_ok;
    st.resident = in.bank_genuinely_resident;
    st.full_pipeline_device = in.full_device_pipeline;
    st.device_timed = in.device_event_timing;
    st.production_qualified =
        in.v3_config_selected && in.production_dimensions && in.full_page_schedule &&
        in.real_m128_workload && in.canonical_packed_bank && in.native_provider_linked &&
        in.arch_backend_selected && in.exactness_selfqual_ok && in.bank_genuinely_resident &&
        in.native_tensor_executed && in.full_device_pipeline && in.no_per_barrier_host_sync &&
        in.no_cpu_fallback && in.no_dense_int8_as_native && in.no_scalar_cuda_as_native &&
        in.device_event_timing && in.cpu_gpu_byte_exact && in.production_provenance_recorded &&
        in.corruption_gate_ok && in.production_readiness_tests_pass;
    st.peak_ready = st.production_qualified;
    if (!st.peak_ready) {
        st.deficit = "peak_ready_prerequisites_incomplete";
    }
    return st;
}

/**
 * Episode / datacenter helper: map honest residency bits into peak inputs.
 * Callers MUST assign peak_ready = DeriveRCPeakReady(...).peak_ready — never
 * invent true. Missing production bits stay false (fail-closed).
 */
struct RCEpisodePeakBits {
    bool cuda_episode_compiled{false};
    bool device_bank_resident{false};
    bool device_state_resident{false};
    bool resident_native_mxfp4_qualified{false};
    bool resident_native_mxfp4_attempted{false};
    bool device_digest{false};
    bool full_device_pipeline{false}; // permute/mix/Extract/digest on device
    bool no_per_barrier_host_sync{false};
    bool cpu_gpu_byte_exact{false};
    bool full_page_schedule{false};
    bool v3_config_selected{false};
    bool production_dimensions{false};
};

[[nodiscard]] inline RCPeakReadyInputs MakeRCPeakReadyInputsFromEpisode(
    const RCEpisodePeakBits& b)
{
    RCPeakReadyInputs in;
    in.v3_config_selected = b.v3_config_selected;
    in.production_dimensions = b.production_dimensions;
    in.full_page_schedule = b.full_page_schedule;
    in.native_provider_linked = b.cuda_episode_compiled;
    in.arch_backend_selected = b.resident_native_mxfp4_qualified;
    in.exactness_selfqual_ok = b.resident_native_mxfp4_qualified;
    in.bank_genuinely_resident = b.device_bank_resident && b.device_state_resident;
    in.native_tensor_executed =
        b.resident_native_mxfp4_attempted && b.resident_native_mxfp4_qualified;
    in.full_device_pipeline = b.full_device_pipeline && b.device_digest;
    in.no_per_barrier_host_sync = b.no_per_barrier_host_sync;
    in.cpu_gpu_byte_exact = b.cpu_gpu_byte_exact;
    // Remaining production readiness latches stay false until campaigns land.
    return in;
}

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_PEAK_READY_H
