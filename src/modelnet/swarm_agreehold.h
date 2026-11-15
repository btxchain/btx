// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGREEHOLD_H
#define BITCOIN_MODELNET_SWARM_AGREEHOLD_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmAgreeHold {
    std::string agreement_id;
    bool agreed;
    bool want_settle;
};

struct SwarmAgreeHoldResult {
    std::string code;
    bool settled;
    int64_t atoms;
};

SwarmAgreeHoldResult SwarmHoldAgreement(const SwarmAgreeHold& agreement, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGREEHOLD_H
