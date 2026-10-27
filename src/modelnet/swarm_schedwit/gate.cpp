// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_schedwit/gate.h>

#include <modelnet/swarm_schedwit/blank.h>
#include <modelnet/swarm_schedwit/codes.h>
#include <modelnet/swarm_schedwit/replay.h>

namespace modelnet {

SwarmSchedWitnessDecision SwarmSchedWitnessDecide(const SwarmSchedWitnessBook& book, const std::string& witness)
{
    std::string err;
    if (!SwarmSchedWitnessBlank{}.accept(witness, err)) {
        return SwarmSchedWitnessDecision{err, false};
    }
    if (SwarmSchedWitnessIsReplay(book, witness)) {
        return SwarmSchedWitnessDecision{std::string{kSwarmSchedWitnessReplay}, false};
    }
    return SwarmSchedWitnessDecision{{}, true};
}

} // namespace modelnet
