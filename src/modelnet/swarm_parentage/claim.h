// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PARENTAGE_CLAIM_H
#define BITCOIN_MODELNET_SWARM_PARENTAGE_CLAIM_H

#include <string>

namespace modelnet {

/**
 * Classify a claim of a checkpoint id.
 * An empty checkpoint sets err to LINEAGE.
 * Any other checkpoint sets err to NOT_TRUST.
 * The function returns false on both paths.
 * It has no ledger parameter, so a checkpoint id alone stores nothing.
 * A checkpoint id alone is not trust.
 */
bool SwarmParentageClassifyClaim(const std::string& checkpoint, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PARENTAGE_CLAIM_H
