// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_guesthold/check.h>

#include <modelnet/swarm_guesthold/codes.h>
#include <modelnet/swarm_guesthold/gate.h>
#include <modelnet/swarm_guesthold/stay.h>

namespace modelnet {

bool SwarmGuestHoldCheck::Apply(SwarmGuestHoldBook& book, const std::string& name, std::string& err) const
{
    const SwarmGuestHoldDecision decision = SwarmGuestHoldDecide(book, name);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(name) || !book.contains(name)) {
        if (book.contains(name)) {
            err = kSwarmGuestHoldReplay;
        } else {
            err = kSwarmGuestHoldGuest;
        }
        return false;
    }
    err = SwarmGuestHoldStay{}.refusal();
    return false;
}

} // namespace modelnet
