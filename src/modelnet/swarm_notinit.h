// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTINIT_H
#define BITCOIN_MODELNET_SWARM_NOTINIT_H

#include <string>

namespace modelnet {

struct SwarmNotInit {
    std::string node_id;
    bool want_init{false};
    bool want_shutdown{false};
};

struct SwarmNotInitResult {
    std::string code;
    bool initialized{false};
    bool shutdown{false};
};

/** Record a note only. This note does not start or stop a process. */
SwarmNotInitResult SwarmNoteNotInit(const SwarmNotInit& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTINIT_H
