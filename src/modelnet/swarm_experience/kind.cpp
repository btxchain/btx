// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_experience/kind.h>

#include <modelnet/swarm_experience/error.h>

namespace modelnet {

bool ExperienceKindAllowed(const std::string& kind, std::string& err)
{
    if (kind == kExperiencePublic || kind == kExperienceSynthetic) {
        err.clear();
        return true;
    }
    err = kExperiencePrivateData;
    return false;
}

} // namespace modelnet
