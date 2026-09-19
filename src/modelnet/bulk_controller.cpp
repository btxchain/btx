// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/bulk_controller.h>

#include <algorithm>

namespace modelnet {

void LowPriorityBulkController::ObserveRtt(double rtt_ms)
{
    if (rtt_ms < 1.0) rtt_ms = 1.0;
    m_rtt_ms = rtt_ms;
    if (m_baseline_rtt_ms < 1.0) m_baseline_rtt_ms = rtt_ms;
    const double ratio = m_rtt_ms / m_baseline_rtt_ms;
    if (ratio > 1.5 || m_backpressure) {
        m_pressure = true;
        m_clear_ticks = 0;
        m_share = std::max(0.05, m_share * 0.5);
        if (m_share > 0.08) m_share = 0.08;
        return;
    }
    if (m_pressure) {
        if (ratio < 1.1) ++m_clear_ticks;
        else m_clear_ticks = 0;
        if (m_clear_ticks < 2) {
            m_share = 0.08;
            return;
        }
        m_pressure = false;
        m_clear_ticks = 0;
    }
    if (ratio < 1.1) m_share = std::min(0.20, m_share + 0.04);
    else m_share = 0.12;
}

void LowPriorityBulkController::ObserveBackpressure(bool saturated)
{
    m_backpressure = saturated;
    ObserveRtt(m_rtt_ms);
}

UniValue LowPriorityBulkController::StatusJson() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("background_share", m_share);
    o.pushKV("rtt_ms", m_rtt_ms);
    o.pushKV("baseline_rtt_ms", m_baseline_rtt_ms);
    o.pushKV("backpressure", m_backpressure);
    o.pushKV("pressure_latched", m_pressure);
    o.pushKV("clear_ticks", m_clear_ticks);
    o.pushKV("interactive_priority", true);
    o.pushKV("ranking_authority", false);
    o.pushKV("hysteresis", true);
    return o;
}

} // namespace modelnet
