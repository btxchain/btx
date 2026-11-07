// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SPECSLOT_H
#define BTX_MODELNET_SWARM_SPECSLOT_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory exploration-slot count for a niche. Open stores a positive
 * remainder. Spend subtracts from that remainder. A spend larger than the
 * remainder is refused and the remainder stays.
 *
 * This count does not broadcast, spend, spawn a child process, open a
 * network connection, or use a hostname or IP.
 */
class SwarmSpecSlot {
public:
    /**
     * An empty niche is NICHE. slots < 1 is SLOTS. A second Open for the
     * same niche is REPLAY and leaves the stored remainder. Success stores
     * remaining = slots, clears err, and returns true.
     */
    bool Open(const std::string& niche, int64_t slots, std::string& err);

    /**
     * An unknown niche is NICHE. slots < 1 is SLOTS. slots greater than the
     * remainder is EXHAUSTED and leaves the remainder. Success subtracts
     * slots, clears err, and returns true.
     */
    bool Spend(const std::string& niche, int64_t slots, std::string& err);

    /** -1 when the niche was never opened. */
    int64_t Remaining(const std::string& niche) const;

private:
    std::map<std::string, int64_t> m_remaining;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SPECSLOT_H
