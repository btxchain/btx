// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_guesthold/gate.h>

#include <modelnet/swarm_guesthold/blank.h>
#include <modelnet/swarm_guesthold/codes.h>
#include <modelnet/swarm_guesthold/replay.h>

namespace modelnet {

SwarmGuestHoldDecision SwarmGuestHoldDecide(const SwarmGuestHoldBook& book, const std::string& name)
{
    std::string err;
    if (!SwarmGuestHoldBlank{}.accept(name, err)) {
        return SwarmGuestHoldDecision{err, false};
    }
    if (SwarmGuestHoldIsReplay(book, name)) {
        return SwarmGuestHoldDecision{std::string{kSwarmGuestHoldReplay}, false};
    }
    return SwarmGuestHoldDecision{{}, true};
}

} // namespace modelnet
