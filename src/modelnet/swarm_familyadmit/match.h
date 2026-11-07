// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAMILYADMIT_MATCH_H
#define BITCOIN_MODELNET_SWARM_FAMILYADMIT_MATCH_H

#include <string>

namespace modelnet {

/**
 * Exact family-id equality.
 * Either side empty is not a match. Comparison is case-sensitive and
 * does not trim.
 */
bool SwarmFamilyAdmitSameFamily(const std::string& family, const std::string& advertised_family);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAMILYADMIT_MATCH_H
