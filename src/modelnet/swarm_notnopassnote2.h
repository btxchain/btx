// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTNOPASSNOTE2_H
#define BITCOIN_MODELNET_SWARM_NOTNOPASSNOTE2_H

#include <string>

namespace modelnet {

struct SwarmNotNoPassNote2 {
    std::string stage_id;
    bool want_pass{false};
};

struct SwarmNotNoPassNote2Result {
    std::string code;
    bool passed{false};
};

SwarmNotNoPassNote2Result SwarmNoteNotNoPassNote2(const SwarmNotNoPassNote2& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTNOPASSNOTE2_H
