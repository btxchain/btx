// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOSEMARGIN_REPLAY_H
#define BITCOIN_MODELNET_SWARM_CLOSEMARGIN_REPLAY_H

#include <modelnet/swarm_closemargin/book.h>

#include <cstdint>

namespace modelnet {

/** True when blocks is already stored. A count other than 160 is never a replay. */
bool SwarmCloseMarginHoldIsReplay(const SwarmCloseMarginHoldBook& book, int64_t blocks);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOSEMARGIN_REPLAY_H
