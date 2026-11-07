// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HOLDROT_REPLAY_H
#define BITCOIN_MODELNET_SWARM_HOLDROT_REPLAY_H

#include <modelnet/swarm_holdrot/book.h>

#include <string>

namespace modelnet {

/** True when holdout is already stored. An empty holdout is never a replay. */
bool SwarmHoldoutRotateIsReplay(const SwarmHoldoutRotateBook& book, const std::string& holdout);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HOLDROT_REPLAY_H
