// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_schedwit/request.h>

#include <modelnet/swarm_schedwit/codes.h>
#include <modelnet/swarm_schedwit/gate.h>
#include <modelnet/swarm_schedwit/stay.h>

namespace modelnet {

bool SwarmSchedWitnessRequest::Apply(SwarmSchedWitnessBook& book, const std::string& witness, std::string& err) const
{
    const SwarmSchedWitnessDecision decision = SwarmSchedWitnessDecide(book, witness);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(witness) || !book.contains(witness)) {
        if (book.contains(witness)) {
            err = kSwarmSchedWitnessReplay;
        } else {
            err = kSwarmSchedWitnessWitness;
        }
        return false;
    }
    err = SwarmSchedWitnessStay{}.refusal();
    return false;
}

} // namespace modelnet
