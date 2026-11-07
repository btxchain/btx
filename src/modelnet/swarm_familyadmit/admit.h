// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAMILYADMIT_ADMIT_H
#define BITCOIN_MODELNET_SWARM_FAMILYADMIT_ADMIT_H

#include <modelnet/swarm_familyadmit/roster.h>

#include <string>

namespace modelnet {

/**
 * Admit peer when it claims compatibility and advertised_family equals family.
 * On success the peer is stored with family and err is cleared.
 * On failure nothing is stored and err is FAMILY, FALSE_COMPAT,
 * NOT_ADMITTED, or REPLAY. A replay leaves the first family in place.
 * This does not connect the peer and does not record a seed.
 */
bool SwarmFamilyAdmitApply(SwarmFamilyAdmitRoster& roster,
                            const std::string& peer,
                            const std::string& family,
                            const std::string& advertised_family,
                            bool claims_compatible,
                            std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAMILYADMIT_ADMIT_H
