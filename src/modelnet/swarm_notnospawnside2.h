// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSPAWNSIDE2_H
#define BTX_MODELNET_SWARM_NOTNOSPAWNSIDE2_H

#include <string>

namespace modelnet {

struct SwarmNotNoSpawnSide2 {
    std::string name_id;
    bool want_spawn{false};
};

struct SwarmNotNoSpawnSide2Result {
    std::string code;
    bool spawned{false};
};

SwarmNotNoSpawnSide2Result SwarmNoteNotNoSpawnSide2(const SwarmNotNoSpawnSide2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSPAWNSIDE2_H
