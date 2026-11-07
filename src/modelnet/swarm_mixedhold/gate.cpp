// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_mixedhold/gate.h>

#include <modelnet/swarm_mixedhold/blank.h>
#include <modelnet/swarm_mixedhold/codes.h>
#include <modelnet/swarm_mixedhold/replay.h>

namespace modelnet {

SwarmMixedHoldDecision SwarmMixedHoldDecide(const SwarmMixedHoldBook& book, const std::string& name)
{
    std::string err;
    if (!SwarmMixedHoldBlank{}.accept(name, err)) {
        return SwarmMixedHoldDecision{err, false};
    }
    if (SwarmMixedHoldIsReplay(book, name)) {
        return SwarmMixedHoldDecision{std::string{kSwarmMixedHoldReplay}, false};
    }
    return SwarmMixedHoldDecision{{}, true};
}

} // namespace modelnet
