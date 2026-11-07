// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rescap/apply.h>

#include <modelnet/swarm_rescap/codes.h>
#include <modelnet/swarm_rescap/gate.h>
#include <modelnet/swarm_rescap/limits.h>
#include <modelnet/swarm_rescap/stay.h>

namespace modelnet {

bool SwarmResCapApply::Apply(SwarmResCapBook& book, int64_t threads, std::string& err) const
{
    const SwarmResCapDecision decision = SwarmResCapDecide(book, threads);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(threads) || !book.contains(threads)) {
        if (book.contains(threads)) {
            err = kSwarmResCapReplay;
        } else if (threads < kSwarmResCapMinThreads) {
            err = kSwarmResCapCap;
        } else {
            err = kSwarmResCapCapped;
        }
        return false;
    }
    err = SwarmResCapStay{}.refusal();
    return false;
}

} // namespace modelnet
