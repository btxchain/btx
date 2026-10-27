// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/flag.h>

#include <modelnet/swarm_privfam/blank.h>
#include <modelnet/swarm_privfam/codes.h>

namespace modelnet {

SwarmPrivFamFlag SwarmPrivFamClassify(const std::string& family, bool private_flag)
{
    if (SwarmPrivFamBlank(family)) return SwarmPrivFamFlag::Family;
    if (!private_flag) return SwarmPrivFamFlag::Public;
    return SwarmPrivFamFlag::Private;
}

const char* SwarmPrivFamFlagCode(SwarmPrivFamFlag flag)
{
    switch (flag) {
    case SwarmPrivFamFlag::Family:
        return kSwarmPrivFamFamily;
    case SwarmPrivFamFlag::Public:
        return kSwarmPrivFamPublic;
    case SwarmPrivFamFlag::Private:
        return nullptr;
    }
    return kSwarmPrivFamFamily;
}

} // namespace modelnet
