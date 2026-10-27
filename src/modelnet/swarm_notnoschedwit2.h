// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSCHEDWIT2_H
#define BTX_MODELNET_SWARM_NOTNOSCHEDWIT2_H

#include <string>

namespace modelnet {

struct SwarmNotNoSchedWit2 {
    std::string witness_id;
    bool scheduler{false};
    bool want_sign{false};
};

struct SwarmNotNoSchedWit2Result {
    std::string code;
    bool signed_ok{false};
};

SwarmNotNoSchedWit2Result SwarmNoteNotNoSchedWit2(const SwarmNotNoSchedWit2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSCHEDWIT2_H
