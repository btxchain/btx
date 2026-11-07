// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTDEP_H
#define BITCOIN_MODELNET_SWARM_NOTDEP_H

#include <string>

namespace modelnet {

struct SwarmNotDep {
    std::string dep_id;
    bool want_detect{false};
};

struct SwarmNotDepResult {
    std::string code;
    bool detected{false};
    bool required{false};
};

/** Record a note only. This note does not probe the filesystem. */
SwarmNotDepResult SwarmNoteNotDep(const SwarmNotDep& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTDEP_H
