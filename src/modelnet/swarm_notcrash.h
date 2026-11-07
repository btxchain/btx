// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTCRASH_H
#define BITCOIN_MODELNET_SWARM_NOTCRASH_H

#include <string>

namespace modelnet {

struct SwarmNotCrash {
    std::string node_id;
    bool want_recover{false};
};

struct SwarmNotCrashResult {
    std::string code;
    bool recovered{false};
    bool restarted{false};
};

/** Record a note only. Never reports that a process was killed or restarted. */
SwarmNotCrashResult SwarmNoteNotCrash(const SwarmNotCrash& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTCRASH_H
