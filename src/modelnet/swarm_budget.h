// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_BUDGET_H
#define BTX_MODELNET_SWARM_BUDGET_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory research-slot budget. Open stores a positive remainder for an
 * experiment. Spend subtracts from that remainder. A remainder of zero
 * rejects further spend. This ledger does not broadcast, spawn a child
 * process, open a network connection, or move BTX atoms.
 */
class SwarmResearchBudget {
public:
    /**
     * An empty experiment is EXPERIMENT. slots < 1 is BUDGET. A second Open
     * for the same experiment is REPLAY and leaves the stored remainder.
     * Success stores remaining = slots and clears err.
     */
    bool Open(const std::string& experiment, int64_t slots, std::string& err);

    /**
     * An unknown experiment is EXPERIMENT. slots < 1 is BUDGET. slots greater
     * than the remainder is EXHAUSTED and leaves the remainder. Success
     * subtracts slots and clears err.
     */
    bool Spend(const std::string& experiment, int64_t slots, std::string& err);

    /** -1 when the experiment was never opened. */
    int64_t Remaining(const std::string& experiment) const;

private:
    std::map<std::string, int64_t> m_remaining;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_BUDGET_H
