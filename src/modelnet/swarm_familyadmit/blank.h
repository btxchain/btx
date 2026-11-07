// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAMILYADMIT_BLANK_H
#define BITCOIN_MODELNET_SWARM_FAMILYADMIT_BLANK_H

#include <string>

namespace modelnet {

/**
 * An empty peer or an empty family cannot be stored.
 * Advertised text and the compatibility flag do not change this.
 */
bool SwarmFamilyAdmitBlank(const std::string& peer, const std::string& family);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAMILYADMIT_BLANK_H
