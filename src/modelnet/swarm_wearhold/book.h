// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WEARHOLD_BOOK_H
#define BITCOIN_MODELNET_SWARM_WEARHOLD_BOOK_H

#include <modelnet/swarm_wearhold/record.h>

#include <cstdint>

namespace modelnet {

/**
 * The one joule count stored by a successful Measure.
 * store refuses a count below 1 and refuses a second store.
 * A refused store leaves the first joule count in place.
 * There is no method that charges atoms or replaces the stored count.
 */
class SwarmWearHoldBook {
public:
    bool measured() const;

    /** The stored joule count, or 0 when nothing is stored. */
    int64_t joules() const;

    /**
     * Store joules when the count is at least 1 and the book is empty.
     * On refusal the book is unchanged.
     */
    bool store(int64_t joules);

private:
    bool m_stored{false};
    SwarmWearHoldRecord m_record;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WEARHOLD_BOOK_H
