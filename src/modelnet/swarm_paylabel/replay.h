// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYLABEL_REPLAY_H
#define BITCOIN_MODELNET_SWARM_PAYLABEL_REPLAY_H

#include <modelnet/swarm_paylabel/book.h>

#include <string>

namespace modelnet {

/**
 * True when label is exactly "work-payment" and that label is already stored.
 * profit-share, empty, and any other label are not a replay.
 */
bool SwarmPayLabelIsReplay(const SwarmPayLabelBook& book, const std::string& label);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYLABEL_REPLAY_H
