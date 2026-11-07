// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_wearhold/meter.h>

#include <modelnet/swarm_wearhold/codes.h>
#include <modelnet/swarm_wearhold/gate.h>

namespace modelnet {

bool SwarmWearHoldMeter::Apply(SwarmWearHoldBook& book, int64_t joules, std::string& err) const
{
    const std::string refusal = SwarmWearHoldRefusal(book, joules);
    if (!refusal.empty()) {
        err = refusal;
        return false;
    }
    if (!book.store(joules)) {
        if (book.measured()) {
            err = kSwarmWearHoldReplay;
        } else {
            err = kSwarmWearHoldMeasure;
        }
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
