// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXECNBHD_SHARE_H
#define BITCOIN_MODELNET_SWARM_EXECNBHD_SHARE_H

#include <modelnet/swarm_execnbhd/seating.h>

#include <string>

namespace modelnet {

/**
 * Decide whether two seated peers are in the same trust domain.
 * An unknown peer, or a peer that is not seated, is refused.
 * Different trust domains are refused and do not share a page.
 * The same trust domain is accepted. This is not a byte transfer.
 * The function has no byte counter to advance.
 */
bool SwarmExecNbhdShareKv(const SwarmExecNbhdSeating& seating, const std::string& left_peer,
                          const std::string& right_peer, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXECNBHD_SHARE_H
