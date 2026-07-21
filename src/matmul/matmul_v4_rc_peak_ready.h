// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_PEAK_READY_H
#define BTX_MATMUL_MATMUL_V4_RC_PEAK_READY_H

#include <cstdint>
#include <string>

// Derived peak_ready — never set manually by callers.

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

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_PEAK_READY_H
