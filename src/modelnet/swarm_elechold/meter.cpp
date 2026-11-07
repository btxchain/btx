// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_elechold/meter.h>

#include <modelnet/swarm_elechold/codes.h>
#include <modelnet/swarm_elechold/gate.h>

namespace modelnet {

bool SwarmElecHoldMeter::Apply(SwarmElecHoldBook& book, int64_t watt_hours, std::string& err) const
{
    const std::string refusal = SwarmElecHoldRefusal(book, watt_hours);
    if (!refusal.empty()) {
        err = refusal;
        return false;
    }
    if (!book.store(watt_hours)) {
        if (book.measured()) {
            err = kSwarmElecHoldReplay;
        } else {
            err = kSwarmElecHoldMeasure;
        }
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
