// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_familyadmit/match.h>

namespace modelnet {

bool SwarmFamilyAdmitSameFamily(const std::string& family, const std::string& advertised_family)
{
    if (family.empty() || advertised_family.empty()) return false;
    return family == advertised_family;
}

} // namespace modelnet
