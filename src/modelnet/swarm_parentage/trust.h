// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PARENTAGE_TRUST_H
#define BITCOIN_MODELNET_SWARM_PARENTAGE_TRUST_H

#include <string>

namespace modelnet {

/**
 * Classify a trust request.
 * An unknown checkpoint sets err to LINEAGE.
 * A known checkpoint sets err to NOT_TRUST.
 * The function returns false on both paths.
 * trusted stays false. This function does not report trust.
 */
bool SwarmParentageClassifyTrust(bool known, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PARENTAGE_TRUST_H
