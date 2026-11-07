// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISPUTEMOVE_H
#define BITCOIN_MODELNET_SWARM_DISPUTEMOVE_H

#include <cstdint>
#include <string>

namespace modelnet {

enum class SwarmDisputeMove { Open = 0, Evidence, Refused, Accepted };

struct SwarmDisputeStep {
    std::string dispute_id;
    SwarmDisputeMove state;
    bool receipt_signed;
    bool outpoint_known;
    bool want_settle;
};

struct SwarmDisputeStepResult {
    std::string code;
    SwarmDisputeMove state;
    bool settled;
    bool broadcast;
    int64_t atoms;
};

SwarmDisputeStepResult SwarmStepDispute(const SwarmDisputeStep& step, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISPUTEMOVE_H
