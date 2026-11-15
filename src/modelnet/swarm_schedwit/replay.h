// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCHEDWITNESS_REPLAY_H
#define BITCOIN_MODELNET_SWARM_SCHEDWITNESS_REPLAY_H

#include <modelnet/swarm_schedwit/book.h>

#include <string>

namespace modelnet {

/** True when witness is already stored. An empty witness is never a replay. */
bool SwarmSchedWitnessIsReplay(const SwarmSchedWitnessBook& book, const std::string& witness);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCHEDWITNESS_REPLAY_H
