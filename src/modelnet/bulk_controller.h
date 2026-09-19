// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_BULK_CONTROLLER_H
#define BITCOIN_MODELNET_BULK_CONTROLLER_H

#include <univalue.h>

namespace modelnet {

/**
 * Spec §8.2: low-priority bulk (hydration / origin ingest) yields to
 * interactive piece traffic. Never a ranking or monetary signal.
 */
class LowPriorityBulkController {
    double m_baseline_rtt_ms{50.0};
    double m_rtt_ms{50.0};
    bool m_backpressure{false};
    double m_share{0.15};
    int m_clear_ticks{0};
    bool m_pressure{false};

public:
    void ObserveRtt(double rtt_ms);
    void ObserveBackpressure(bool saturated);
    double BackgroundShare() const { return m_share; }
    bool InteractiveHasPriority() const { return true; }
    UniValue StatusJson() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_BULK_CONTROLLER_H
