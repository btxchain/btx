// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAMILYADMIT_COMPAT_H
#define BITCOIN_MODELNET_SWARM_FAMILYADMIT_COMPAT_H

#include <string>

namespace modelnet {

/**
 * How an advertisement relates to the local family.
 * Match is the only result that may be stored. The other results store nothing.
 */
enum class SwarmFamilyAdmitCompat {
    Match,
    Family,
    FalseCompat,
    NotAdmitted,
};

/**
 * Classify one Admit attempt. This does not look at peers already stored.
 * Empty peer or family is Family.
 * claims_compatible false is NotAdmitted, including when the strings match
 * and including when they differ.
 * claims_compatible true with a different advertised family is FalseCompat.
 */
SwarmFamilyAdmitCompat SwarmFamilyAdmitClassify(const std::string& peer,
                                                 const std::string& family,
                                                 const std::string& advertised_family,
                                                 bool claims_compatible);

/**
 * Refusal code for a non-match, or nullptr for Match.
 */
const char* SwarmFamilyAdmitCompatCode(SwarmFamilyAdmitCompat compat);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAMILYADMIT_COMPAT_H
