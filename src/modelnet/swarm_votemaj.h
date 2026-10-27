// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_VOTEMAJ_H
#define BITCOIN_MODELNET_SWARM_VOTEMAJ_H

#include <string>

namespace modelnet {

struct SwarmVoteMaj {
    std::string vote_id;
    bool majority;
    bool want_graduate;
    bool want_hide;
};

struct SwarmVoteMajResult {
    std::string code;
    bool graduated;
    bool hidden;
};

SwarmVoteMajResult SwarmNoteMajority(const SwarmVoteMaj& vote, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_VOTEMAJ_H
