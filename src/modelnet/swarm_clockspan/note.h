// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOCKSPAN_NOTE_H
#define BITCOIN_MODELNET_SWARM_CLOCKSPAN_NOTE_H

#include <modelnet/swarm_clockspan/book.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Notes one block spacing.
 * seconds below 1 is RANGE and the book stays as it was.
 * Any other positive seconds that is not 90 is SPACING and the book stays
 * as it was. A second 90 is REPLAY and leaves the first spacing.
 * Those checks run in that order. A success stores 90 and clears err.
 * Nothing is mined.
 */
class SwarmClockSpanNote {
public:
    bool Apply(SwarmClockSpanBook& book, int64_t seconds, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOCKSPAN_NOTE_H
