// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_COUPLED_NETCOST_H
#define BTX_MATMUL_MATMUL_V4_RC_COUPLED_NETCOST_H

#include <algorithm>
#include <cstdint>

// ENC_RC Stage G — SOFTWARE interconnect cost model (SIMULATED).
//
// Injects a configurable per-barrier exchange latency for fabric (NVLink /
// Infinity Fabric class) vs PCIe. Used ONLY to report a simulated slowdown
// factor on the *exchange portion* of an episode.
//
// *************************************************************************
// SIMULATED / NOT SILICON / NOT EVIDENCE for Stage-I gate 4
// (≥7× NVLink-vs-PCIe on the same chips). Real B200/MI355X/NVLink campaigns
// are still required. Do not treat any number from this header as a GO input.
// *************************************************************************

namespace matmul::v4::rc {

/** Configurable per-barrier exchange costs (microseconds). */
struct RCCoupNetCostParams {
    double fabric_us{5.0};   // coherent fabric (NVLink-class) per barrier
    double pcie_us{80.0};    // PCIe cluster hop per barrier (default ~16×)
    uint32_t barriers{4};    // exchange events per episode
};

/** Result of the software model — always labeled simulated. */
struct RCCoupNetCostSim {
    double fabric_exchange_us{0.0};
    double pcie_exchange_us{0.0};
    /** pcie_exchange_us / fabric_exchange_us (exchange portion only). */
    double exchange_slowdown_factor{0.0};
    bool simulated{true};
    /** Hard-coded: never admissible as Stage-I gate 4 evidence. */
    bool stage_i_gate4_evidence{false};
    const char* label{"SIMULATED / NOT EVIDENCE for Stage-I gate 4 (≥7× same chips)"};
};

/**
 * Inject per-barrier exchange cost and report simulated NVLink-vs-PCIe
 * slowdown on the exchange portion only.
 *
 * Does NOT model compute, paging, or host orchestration. Does NOT claim
 * silicon measurement.
 */
[[nodiscard]] inline RCCoupNetCostSim SimulateCoupledExchangeNetCost(
    const RCCoupNetCostParams& p = {})
{
    RCCoupNetCostSim out;
    const uint32_t b = std::max<uint32_t>(1, p.barriers);
    const double fab = std::max(0.0, p.fabric_us);
    const double pci = std::max(0.0, p.pcie_us);
    out.fabric_exchange_us = fab * static_cast<double>(b);
    out.pcie_exchange_us = pci * static_cast<double>(b);
    out.exchange_slowdown_factor =
        (fab > 0.0) ? (out.pcie_exchange_us / out.fabric_exchange_us) : 0.0;
    out.simulated = true;
    out.stage_i_gate4_evidence = false;
    return out;
}

/** Stage-I gate 4 threshold (real silicon only). */
inline constexpr double kStageIGate4NvlinkVsPcieMin = 7.0;

/**
 * Never returns true for simulated results. Kept for call-site clarity:
 * silicon campaigns must set simulated=false AND measured_factor≥7.
 */
[[nodiscard]] inline bool StageIGate4NvlinkPass(double measured_factor, bool simulated)
{
    if (simulated) return false;
    return measured_factor >= kStageIGate4NvlinkVsPcieMin;
}

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_COUPLED_NETCOST_H
