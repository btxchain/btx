// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REGCHECK_H
#define BITCOIN_MODELNET_SWARM_REGCHECK_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmRegCheck {
    std::string check_id;
    bool script_present;
    bool utxo_known;
    bool want_mine;
    bool want_broadcast;
};

struct SwarmRegCheckResult {
    std::string code;
    bool mined;
    bool broadcast;
    int64_t blocks;
    bool script_ok;
};

SwarmRegCheckResult SwarmCheckRegtest(const SwarmRegCheck& check, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REGCHECK_H
