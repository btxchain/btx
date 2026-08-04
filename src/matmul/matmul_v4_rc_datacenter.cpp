// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_datacenter.h>

#include <cuda/matmul_v4_rc_episode_context.h>
#include <matmul/matmul_v4_rc_peak_ready.h>

#include <limits>

namespace matmul::v4::rc::dc {

bool RCCoupFullBankScheduleActive()
{
    // Compile-time only. NEVER read getenv here — these flags flow into
    // RecomputeCoupledPuzzleReference and change digests (latent chain split).
    // Harness may still force legacy via RCCoupOptions::full_bank_schedule=false
    // only when the caller constructs options explicitly after defaulting.
    return kRCCoupFullBankScheduleEnabled;
}

bool RCCoupMaterialExchangeActive()
{
    // Compile-time only. Env must not touch consensus (see full-bank note).
    return kRCCoupMaterialExchangeEnabled;
}

RCDcStatus ProbeRCDcStatus()
{
    RCDcStatus st;
    st.full_bank_schedule = RCCoupFullBankScheduleActive();
    st.material_exchange = RCCoupMaterialExchangeActive();
    st.three_axis_wire = kRCThreeAxisScheduleWireEnabled;
    st.miner_batch_q_default_on = true;
    st.miner_batch_q = kRCMinerBatchQDefault;
    st.exchange_rows_default = kRCCoupExchangeRowsDefault;
    st.gkr_arbiter = false;
    st.cuda_episode_compiled = matmul_v4::cuda::IsRcEpisodeCudaCompiled();
    st.arch_key = matmul_v4::cuda::RcEpisodeCudaArchKey();

    // Derive cuda_episode_ready / peak_ready — never `compiled == ready`.
    RCEpisodePeakBits bits;
    bits.cuda_episode_compiled = st.cuda_episode_compiled;
    bits.full_page_schedule = st.full_bank_schedule;
    // Production dims / native / full device pipeline remain false until
    // silicon campaigns + Agent D/E latches land (fail-closed).
    const RCPeakReadyStatus peak = DeriveRCPeakReady(MakeRCPeakReadyInputsFromEpisode(bits));
    st.peak_ready = peak.peak_ready;
    st.cuda_episode_ready = peak.peak_ready;

    // Heights remain INT32_MAX — levers are configured but publicly inert.
    if (!st.cuda_episode_compiled) {
        st.deficit = "episode_graph_unwired; heights_int32_max";
    } else if (!st.full_bank_schedule || !st.material_exchange || !st.three_axis_wire) {
        st.deficit = "dc_lever_incomplete";
    } else if (!st.peak_ready) {
        st.deficit = peak.deficit.empty() ? "heights_int32_max;peak_ready_prerequisites_incomplete"
                                          : (peak.deficit + "; heights_int32_max");
    } else {
        st.deficit = "heights_int32_max";
    }
    return st;
}

uint32_t BankPagesForPackedGiB(double gib, uint32_t lobe_width)
{
    if (gib <= 0.0 || lobe_width == 0) return 0;
    const double page_bytes =
        static_cast<double>(lobe_width) * static_cast<double>(lobe_width) * kRCMxPackedBytesPerElem;
    const double target = gib * (1024.0 * 1024.0 * 1024.0);
    const double pages = target / page_bytes;
    if (pages >= static_cast<double>(std::numeric_limits<uint32_t>::max())) {
        return std::numeric_limits<uint32_t>::max();
    }
    const auto n = static_cast<uint32_t>(pages + 0.999);
    return n == 0 ? 1 : n;
}

} // namespace matmul::v4::rc::dc
