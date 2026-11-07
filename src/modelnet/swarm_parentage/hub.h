// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PARENTAGE_HUB_H
#define BITCOIN_MODELNET_SWARM_PARENTAGE_HUB_H

#include <string>

namespace modelnet {

/**
 * Classify a hub card.
 * An empty card sets err to CARD.
 * Any other card sets err to NOT_AUTHORITY.
 * The function returns false on both paths.
 * It has no ledger parameter, so it cannot create a binding or replace a parent.
 * It has no trust parameter, so it cannot mark trust.
 * A hub card is not lineage authority.
 */
bool SwarmParentageClassifyHub(const std::string& checkpoint, const std::string& card, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PARENTAGE_HUB_H
