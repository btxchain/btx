// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FLAGSHIP_INSPECT_H
#define BITCOIN_MODELNET_SWARM_FLAGSHIP_INSPECT_H

#include <string>

namespace modelnet {

class SwarmFlagshipLedger;

/**
 * Read evidence ids. A stage name outside the thirteen is unrecorded
 * and has empty evidence. next_stage is the first stage with no
 * evidence, or empty when all thirteen are recorded.
 * Reading does not pass a stage.
 */
class SwarmFlagshipInspect {
public:
    static bool recorded(const SwarmFlagshipLedger& ledger, const std::string& stage);
    static std::string evidence(const SwarmFlagshipLedger& ledger, const std::string& stage);
    static std::string next_stage(const SwarmFlagshipLedger& ledger);
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FLAGSHIP_INSPECT_H
