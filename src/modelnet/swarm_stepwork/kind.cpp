// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stepwork/kind.h>

#include <modelnet/swarm_experience/kind.h>

#include <string>
#include <string_view>

namespace modelnet {

static_assert(std::string_view{kExperiencePublic} == "public_trajectory", "public kind");
static_assert(std::string_view{kExperienceSynthetic} == "synthetic_trajectory", "synthetic kind");

bool SwarmStepWorkPublicKind(std::string& kind, std::string& err)
{
    kind = kExperiencePublic;
    if (!ExperienceKindAllowed(kind, err)) {
        kind.clear();
        return false;
    }
    return true;
}

} // namespace modelnet
