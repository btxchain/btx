// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/gate.h>

#include <modelnet/swarm_privfam/blank.h>
#include <modelnet/swarm_privfam/codes.h>
#include <modelnet/swarm_privfam/flag.h>
#include <modelnet/swarm_privfam/replay.h>

namespace modelnet {

std::string SwarmPrivFamRefusal(const SwarmPrivFamRoster& roster,
                                const std::string& family,
                                bool private_flag)
{
    if (SwarmPrivFamBlank(family)) return std::string{kSwarmPrivFamFamily};
    if (SwarmPrivFamIsReplay(roster, family)) return std::string{kSwarmPrivFamReplay};
    const SwarmPrivFamFlag flag = SwarmPrivFamClassify(family, private_flag);
    if (flag != SwarmPrivFamFlag::Private) {
        const char* code = SwarmPrivFamFlagCode(flag);
        if (code == nullptr) return std::string{kSwarmPrivFamFamily};
        return std::string{code};
    }
    return {};
}

} // namespace modelnet
