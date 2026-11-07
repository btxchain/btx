// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCHEDWITNESS_REQUEST_H
#define BITCOIN_MODELNET_SWARM_SCHEDWITNESS_REQUEST_H

#include <modelnet/swarm_schedwit/book.h>

#include <string>

namespace modelnet {

/**
 * Records one witness and leaves it unsigned.
 * An empty witness is WITNESS and the book stays as it was.
 * A new non-empty witness is stored. The call returns false and err is NOT_SIGNED.
 * A second Sign of the same witness is REPLAY and leaves the first witness.
 * Those checks run in that order. Nothing is signed, no spend is armed,
 * and no key is attached.
 */
class SwarmSchedWitnessRequest {
public:
    bool Apply(SwarmSchedWitnessBook& book, const std::string& witness, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCHEDWITNESS_REQUEST_H
