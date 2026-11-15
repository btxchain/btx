// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOCKSPAN_BOOK_H
#define BITCOIN_MODELNET_SWARM_CLOCKSPAN_BOOK_H

#include <modelnet/swarm_clockspan/record.h>

#include <cstdint>

namespace modelnet {

/**
 * The one spacing stored by a successful Note.
 * store refuses a seconds value that is not 90 and refuses a second store.
 * A refused store leaves the first spacing in place.
 * There is no method that mines a block or replaces the stored spacing.
 */
class SwarmClockSpanBook {
public:
    bool noted() const;

    /** 90 when a spacing is stored, otherwise 0. */
    int64_t spacing() const;

    /**
     * Store seconds when it is 90 and the book is empty.
     * On refusal the book is unchanged.
     */
    bool store(int64_t seconds);

private:
    bool m_stored{false};
    SwarmClockSpanRecord m_record;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOCKSPAN_BOOK_H
