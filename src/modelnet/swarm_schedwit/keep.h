// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCHEDWITNESS_KEEP_H
#define BITCOIN_MODELNET_SWARM_SCHEDWITNESS_KEEP_H

#include <modelnet/swarm_schedwit/book.h>

#include <string>

namespace modelnet {

/**
 * Reads the witness already stored.
 * An unknown witness reads as empty. This function does not write the book
 * and does not sign the witness.
 */
class SwarmSchedWitnessKeep {
public:
    std::string first(const SwarmSchedWitnessBook& book, const std::string& witness) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCHEDWITNESS_KEEP_H
