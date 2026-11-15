// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_WORKCYCLE_H
#define BTX_MODELNET_SWARM_WORKCYCLE_H

#include <string>

namespace modelnet {

/**
 * A local note about one work cycle. cycle_id names the cycle.
 * The six flags are publish, fund, lease, pay, frontier, and graduate.
 * want_advance asks this note to advance the cycle.
 *
 * This note does not advance a cycle. advanced stays false on every
 * path. Nothing is funded and nothing is broadcast. No hostnames or
 * IPs are used.
 */
struct SwarmWorkCycle {
    std::string cycle_id;
    bool publish{false};
    bool fund{false};
    bool lease{false};
    bool pay{false};
    bool frontier{false};
    bool graduate{false};
    bool want_advance{false};
};

/**
 * Outcome of noting a work cycle. advanced stays false: this note does
 * not advance a cycle. Nothing is funded and nothing is broadcast.
 */
struct SwarmWorkCycleResult {
    bool advanced{false};
    std::string code;
};

/**
 * Note a work cycle without advancing, funding, or broadcasting it.
 * Order, first match wins:
 * an empty cycle_id is CYCLE.
 * !fund is FUNDING, even when want_advance is true and even when
 * another flag is also false.
 * !publish, !lease, !pay, !frontier, or !graduate is INCOMPLETE, even
 * when want_advance is true.
 * want_advance is HELD and err is cleared. This note does not advance
 * a cycle.
 * Otherwise the note is NOTED and err is cleared. All six flags true
 * and want_advance false is NOTED.
 * advanced stays false. Nothing is funded and nothing is broadcast.
 */
SwarmWorkCycleResult SwarmNoteWorkCycle(const SwarmWorkCycle& cycle, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_WORKCYCLE_H
