// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAMILYADMIT_GATE_H
#define BITCOIN_MODELNET_SWARM_FAMILYADMIT_GATE_H

#include <modelnet/swarm_familyadmit/roster.h>

#include <string>

namespace modelnet {

/**
 * Refusal code for an Admit that must not store, or empty when the peer
 * may be stored.
 * Empty peer or family is FAMILY. A compatibility claim that does not
 * match is FALSE_COMPAT. A peer that does not claim compatibility is
 * NOT_ADMITTED. A peer already stored, after the attempt would otherwise
 * match, is REPLAY. This function does not modify the roster.
 */
std::string SwarmFamilyAdmitRefusal(const SwarmFamilyAdmitRoster& roster,
                                     const std::string& peer,
                                     const std::string& family,
                                     const std::string& advertised_family,
                                     bool claims_compatible);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAMILYADMIT_GATE_H
