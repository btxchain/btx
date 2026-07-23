// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_residency_plan.h>

#include <algorithm>

namespace matmul::v4::rc {

uint64_t RCResidentHeadroomBytes(uint64_t total_vram_bytes)
{
    const uint64_t proportional =
        static_cast<uint64_t>(static_cast<double>(total_vram_bytes) * kRCResidentHeadroomFraction);
    return std::max(kRCResidentHeadroomBytesFloor, proportional);
}

RCResidencyPlan PlanRCResidency(uint64_t working_set_bytes, uint64_t free_vram_bytes,
                                uint64_t total_vram_bytes)
{
    RCResidencyPlan plan;
    plan.working_set_bytes = working_set_bytes;
    plan.free_vram_bytes = free_vram_bytes;
    plan.total_vram_bytes = total_vram_bytes;
    plan.headroom_bytes = RCResidentHeadroomBytes(total_vram_bytes);
    plan.resident_capable = total_vram_bytes >= kRCResidentVramFloorBytes;

    // Fail-closed: a zero working set is degenerate — do not claim resident.
    if (working_set_bytes == 0) {
        plan.mode = RCAccelResidencyMode::Streamed;
        plan.working_set_fits = false;
        plan.reason = "streamed:degenerate_working_set";
        return plan;
    }

    // Fail-closed: unknown VRAM (driver did not report) — never assume it fits.
    if (total_vram_bytes == 0 || free_vram_bytes == 0) {
        plan.mode = RCAccelResidencyMode::Streamed;
        plan.working_set_fits = false;
        plan.reason = "streamed:vram_unknown";
        return plan;
    }

    // Physical fit uses free VRAM + headroom; guard the addition against wrap.
    const uint64_t need = working_set_bytes + plan.headroom_bytes;
    const bool no_overflow = need >= working_set_bytes; // headroom never huge, but be safe
    plan.working_set_fits = no_overflow && need <= free_vram_bytes;

    if (!plan.working_set_fits) {
        plan.mode = RCAccelResidencyMode::Streamed;
        plan.reason = "streamed:capacity_short";
        return plan;
    }

    // Fits physically. Card-class decides resident vs streamed policy: only a
    // >= 64 GiB card (RTX PRO 6000 Blackwell / datacenter) runs resident; a
    // 24/32 GB consumer card streams even when a toy shape would fit, matching
    // the datacenter-advantage economics (Resident LLM-class wins, Streamed
    // consumer stays consensus-valid but uneconomic).
    if (!plan.resident_capable) {
        plan.mode = RCAccelResidencyMode::Streamed;
        plan.reason = "streamed:small_vram_card";
        return plan;
    }

    plan.mode = RCAccelResidencyMode::Resident;
    plan.reason = "resident:large_vram_fits";
    return plan;
}

} // namespace matmul::v4::rc
