// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSESS_H
#define BTX_MODELNET_SWARM_NOTNOSESS_H

#include <string>

namespace modelnet {

struct SwarmNotNoSess {
    std::string peer_id;
    bool want_session{false};
};

struct SwarmNotNoSessResult {
    std::string code;
    bool connected{false};
    bool mtls{false};
};

// Records a note only. Opens no socket and no mTLS session.
SwarmNotNoSessResult SwarmNoteNotNoSess(const SwarmNotNoSess& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSESS_H
