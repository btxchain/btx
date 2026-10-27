// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PARENTAGE_PROMOTE_H
#define BITCOIN_MODELNET_SWARM_PARENTAGE_PROMOTE_H

#include <string>

namespace modelnet {

/**
 * Classify a realm promotion request.
 * An unknown checkpoint sets err to LINEAGE.
 * A known checkpoint sets err to NOT_GRADUATED.
 * A stored license is parentage text. It is not a training grant and not realm admission.
 * Quality is not realm promotion.
 * The function returns false on both paths.
 * realm_promoted stays false. exact_replay_admitted stays false.
 */
bool SwarmParentageClassifyPromote(bool known, const std::string& license, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PARENTAGE_PROMOTE_H
