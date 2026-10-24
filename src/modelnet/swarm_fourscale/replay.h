// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FOURSCALE_REPLAY_H
#define BITCOIN_MODELNET_SWARM_FOURSCALE_REPLAY_H

#include <modelnet/swarm_fourscale/book.h>

namespace modelnet {

/**
 * True when Open has already planted the four scales.
 * A replay must not write. The steps stay where they are.
 */
bool SwarmFourScaleIsReplay(const SwarmFourScaleBook& book);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FOURSCALE_REPLAY_H
