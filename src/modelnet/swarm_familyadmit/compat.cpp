// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/compat.h>

#include <modelnet/swarm_familyadmit/blank.h>
#include <modelnet/swarm_familyadmit/codes.h>
#include <modelnet/swarm_familyadmit/match.h>

namespace modelnet {

SwarmFamilyAdmitCompat SwarmFamilyAdmitClassify(const std::string& peer,
                                                 const std::string& family,
                                                 const std::string& advertised_family,
                                                 bool claims_compatible)
{
    if (SwarmFamilyAdmitBlank(peer, family)) return SwarmFamilyAdmitCompat::Family;
    if (!claims_compatible) return SwarmFamilyAdmitCompat::NotAdmitted;
    if (!SwarmFamilyAdmitSameFamily(family, advertised_family)) return SwarmFamilyAdmitCompat::FalseCompat;
    return SwarmFamilyAdmitCompat::Match;
}

const char* SwarmFamilyAdmitCompatCode(SwarmFamilyAdmitCompat compat)
{
    switch (compat) {
    case SwarmFamilyAdmitCompat::Family:
        return kSwarmFamilyAdmitFamily;
    case SwarmFamilyAdmitCompat::FalseCompat:
        return kSwarmFamilyAdmitFalseCompat;
    case SwarmFamilyAdmitCompat::NotAdmitted:
        return kSwarmFamilyAdmitNotAdmitted;
    case SwarmFamilyAdmitCompat::Match:
        return nullptr;
    }
    return kSwarmFamilyAdmitFamily;
}

} // namespace modelnet
