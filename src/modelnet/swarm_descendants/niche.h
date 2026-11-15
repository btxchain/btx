// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DESCENDANTS_NICHE_H
#define BITCOIN_MODELNET_SWARM_DESCENDANTS_NICHE_H

#include <string>

namespace modelnet {

/**
 * The three niches this plane assigns: general, coding, and research.
 * Any other channel is refused with NICHE.
 */
bool DescendantNicheKnown(const std::string& channel);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DESCENDANTS_NICHE_H
